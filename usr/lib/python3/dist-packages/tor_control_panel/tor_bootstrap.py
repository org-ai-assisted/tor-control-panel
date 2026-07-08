#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import signal

import os
import re
import time

from sanitize_string.sanitize_string_lib import sanitize_string

from PyQt5.QtCore import *
from PyQt5.QtWidgets import QApplication

## Holds a strong reference to every TorBootstrap thread while it is running so
## Python cannot garbage-collect a QThread that is still executing (which
## crashes with "QThread: Destroyed while thread is still running"). Each thread
## removes itself when it finishes. Callers keep their own bootstrap_thread
## reference to the currently active thread separately.
_active_bootstrap_threads = set()

class TorBootstrap(QThread):
    signal = pyqtSignal(str, int)

    def __init__(self, main):
        super(TorBootstrap, self).__init__(main)

        _active_bootstrap_threads.add(self)
        self.finished.connect(
            lambda: _active_bootstrap_threads.discard(self))

        self.control_cookie_path = '/run/tor/control.authcookie'
        self.control_socket_path = '/run/tor/control'
        self.previous_status = ''
        '''The TAG to phase mapping is mainly according to:
        https://gitweb.torproject.org/tor-launcher.git/tree/src/chrome/locale/en/torlauncher.properties
        '''
        self.tag_phase = {'starting': 'Starting',
                    'conn_pt': 'Connecting to a pluggable transport',
                    'conn_done_pt': "Connected to pluggable transport",
                    'conn_proxy': 'Connecting to the proxy',
                    'conn_done_proxy': 'Connected to the proxy',
                    'conn': 'Connecting to a relay',
                    'conn_dir': 'Connecting to a relay directory',
                    'handshake_dir': 'Finishing handshake with directory server',
                    'onehop_create': 'Establishing an encrypted directory connection',
                    'requesting_status': 'Retrieving network status',
                    'loading_status': 'Loading network status',
                    'loading_keys': 'Loading authority certificates',
                    'enough_dirinfo': 'Loaded enough directory info to build circuits',
                    'ap_conn_pt': 'Connecting to a pluggable transport to build circuits',
                    'ap_conn_done_pt': 'Connected to pluggable transport to build circuits',
                    'ap_conn_proxy': 'Connecting to the proxy to build circuits',
                    'ap_conn_done_proxy': 'Connected to the proxy to build circuits',
                    'ap_conn': 'Connecting to a relay to build circuits',
                    'ap_conn_done': 'Connected to a relay to build circuits',
                    'ap_handshake': 'Finishing handshake with a relay to build circuits',
                    'ap_handshake_done': 'Handshake finished with a relay to build circuits',
                    'requesting_descriptors': 'Requesting relay information',
                    'loading_descriptors': 'Loading relay information',
                    'conn_or': 'Connecting to the Tor network',
                    'conn_done': "Connected to a relay",
                    'handshake': "Handshaking with a relay",
                    'handshake_done': 'Handshake finished with a relay',
                    'handshake_or': 'Finishing handshake with first hop',
                    'circuit_create': 'Establishing a Tor circuit',
                    'done': 'Connected to the Tor network!'}

    def connect_to_control_port(self):
        """Connect and authenticate to Tor's control socket.

        Return a stem Controller on success, or None (after emitting the
        relevant failure phase) if the socket is missing/unreadable or
        authentication fails.
        """
        import stem
        import stem.control
        import stem.socket
        from stem.connection import connect

        ## Step 1: construct a Tor controller. If starting Tor went wrong,
        ## /run/tor/control may never be created, so wait for it for at most
        ## ~5 seconds (25 * 0.2s) before giving up.
        bootstrap_phase = 'Constructing Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        waited_seconds = 0
        while not os.path.exists(self.control_socket_path) and waited_seconds < 5:
            waited_seconds += 0.2
            time.sleep(0.2)

        if not os.path.exists(self.control_socket_path):
            ## The wait loop above timed out: the socket was never created
            ## (Tor not running / not ready yet) -- distinct from a socket that
            ## exists but is unreadable, which the next branch reports.
            print(f"[ERROR] Control socket {self.control_socket_path} does not exist - Tor may not be running.")
            bootstrap_phase = 'socket_error'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
            return None

        if not os.access(self.control_socket_path, os.R_OK):
            print(f"[ERROR] Cannot read control socket at {self.control_socket_path} - permission denied.")
            bootstrap_phase = 'socket_error'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
            return None

        try:
            tor_controller = stem.control.Controller.from_socket_file(self.control_socket_path)
        except stem.SocketError:
            print('Construct Tor Controller Failed: unable to establish a connection')
            bootstrap_phase = 'no_controller'
            bootstrap_percent = 0
            ## After emitting the `no_controller`,
            ## update_bootstrap() will pop the messagebox and quit
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            ## suspend is really useful because we have to wait for our
            ## emitted signal really reach update_bootstrap()
            time.sleep(10)
            return None

        '''Step 2: Controller Authentication
        In order to interact with Tor, we have to do the authentication.
        '''
        bootstrap_phase = 'Authenticating the Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        try:
            tor_controller.authenticate(self.control_cookie_path)
        except stem.connection.IncorrectCookieSize:
            return None  # TODO: the cookie file's size is wrong
        except stem.connection.UnreadableCookieFile:
            # TODO: can we let Tor generate a cookie to fix this situation?
            print('Tor allows for authentication by reading it a cookie file, \
            but we cannot read that file (probably due to permissions)')
            bootstrap_phase = 'cookie_authentication_failed'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
            return None
        except stem.connection.CookieAuthRejected:
            return None  # cookie authentication attempted but the socket does not accept it
        except stem.connection.IncorrectCookieValue:
            return None  # the cookie file's value is rejected
        except Exception:
            return None

        return tor_controller

    def run(self):
        """Thread body: connect to Tor, drive bootstrap, emit (phase, percent)."""
        import stem
        self.tor_controller = self.connect_to_control_port()
        ## If DisableNetwork is 1, toggle it to 0 -- we want Tor to connect to
        ## the network.

        if self.tor_controller is None:
            sys.stdout.write('Controller connection failed.\n')
            sys.stdout.flush()
            ## Return (end this QThread's run) rather than sys.exit(): an
            ## unhandled SystemExit raised inside a QThread can abort the whole
            ## application (the "window vanished" symptom), e.g. when Enable
            ## network briefly restarts Tor and the controller is momentarily
            ## unavailable.
            return

        if self.tor_controller.get_conf('DisableNetwork') == '1':
            self.tor_controller.set_conf('DisableNetwork', '0')
            sys.stdout.write('Toggle DisableNetwork value to 0. Tor is now allowed to connect to the network.\n')
            sys.stdout.flush()
            ## Do not return here: fall through and monitor the bootstrap so the
            ## caller (e.g. the wizard status page) receives progress/completion.

        bootstrap_percent = 0
        while bootstrap_percent < 100:
            bootstrap_phase = ''
            try:
                bootstrap_status = self.tor_controller.get_info("status/bootstrap-phase")
            except stem.ControllerError:
                ## The controller dropped mid-bootstrap (e.g. Tor restarted, the
                ## socket closed). Emit a failure phase and end the thread
                ## cleanly, rather than letting the exception abort the QThread
                ## with no final signal and the UI stuck on the last percent.
                sys.stdout.write('Bootstrap monitoring: controller connection lost.\n')
                sys.stdout.flush()
                self.signal.emit('socket_error', 0)
                return

            if bootstrap_status != self.previous_status:
                progress_match = re.match('.* PROGRESS=([0-9]+).*', bootstrap_status)
                tag_match = re.search(r'TAG=(.*) +SUMMARY', bootstrap_status)
                if not (progress_match and tag_match):
                    ## Unexpected status line: record it and skip, rather than
                    ## crashing the bootstrap thread on a None .group() call.
                    self.previous_status = bootstrap_status
                    time.sleep(0.2)
                    continue
                bootstrap_percent = int(progress_match.group(1))
                bootstrap_tag = tag_match.group(1)
                ''' Use TAG= keyword for bootstrap_phase, according to:
                https://gitweb.torproject.org/tor-launcher.git/plain/README-BOOTSTRAP
                '''
                if bootstrap_tag in self.tag_phase:
                    bootstrap_phase = self.tag_phase[bootstrap_tag]
                else:
                    ## Unknown / newer tag: fall back to Tor's own human-readable
                    ## SUMMARY (sanitized, since it is untrusted) rather than a
                    ## generic placeholder, so e.g. proxy phases still read well.
                    summary_match = re.search(r'SUMMARY="([^"]*)"', bootstrap_status)
                    if summary_match:
                        bootstrap_phase = sanitize_string(summary_match.group(1))
                    else:
                        bootstrap_phase = 'Connecting to the Tor network...'
                    sys.stdout.write('Unknown Bootstrap TAG: %s\n'
                                     % sanitize_string(bootstrap_tag))
                    sys.stdout.flush()
                ## bootstrap_status is untrusted Tor output; sanitize before
                ## writing it to the terminal.
                sys.stdout.write('{0}\n'.format(sanitize_string(bootstrap_status)))
                sys.stdout.flush()
                self.previous_status = bootstrap_status
                self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(0.2)
        # This will guarantee bootstrap_percent 100 is emitted.
        self.signal.emit(bootstrap_phase, bootstrap_percent)


def main():
    app = QApplication(sys.argv)
    thread = TorBootstrap()
    thread.start()
    app.exec_()
