#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import signal

from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QGuiApplication

import os

from subprocess import Popen, PIPE

from tor_control_panel import tor_bootstrap, info, privilege

class RestartTor(QWidget):
    def __init__(self):
        super().__init__()

        self.text = QLabel(self)
        self.bootstrap_progress = QProgressBar(self)
        self.layout = QGridLayout()

        self.setup_ui()

    def setup_ui(self):
        ## Size only; the window is positioned by center() once shown, so a
        ## hardcoded x/y here would just be overridden.
        self.resize(450, 150)
        self.setWindowTitle('Restart Tor')

        self.text.setWordWrap(True)
        self.text.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.text.setMinimumSize(0, 120)

        self.bootstrap_progress.setMinimumSize(400, 0)
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)

        self.layout.addWidget(self.text, 0, 1, 1, 2)
        self.layout.addWidget(self.bootstrap_progress, 1, 1, 1, 1)
        self.setLayout(self.layout)

        self.restart_tor()

    def center(self):
        screen = QGuiApplication.primaryScreen()
        center_point = screen.availableGeometry().center()
        rectangle = self.frameGeometry()
        rectangle.moveCenter(center_point)
        self.move(rectangle.topLeft())

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        self.bootstrap_progress.show()

        if bootstrap_phase == 'no_controller':
            self.text.setText(info.no_controller())
            return
        elif bootstrap_phase == 'cookie_authentication_failed':
            self.text.setText(info.cookie_error())
            return

        if bootstrap_percent == 100:
            self.bootstrap_progress.setValue(100)
            self.text.setText(info.bootstrap_done_text(bootstrap_phase))
        else:
            self.bootstrap_progress.setValue(bootstrap_percent)
            self.text.setText(info.bootstrapping_text(bootstrap_phase))

    def closeEvent(self, event):
        QtCore.QTimer.singleShot(2000, QApplication.instance().quit)
        event.accept()

    def restart_tor(self):
        '''
        Restart tor.
        Use subprocess.Popen instead of subprocess.call in order to catch
        possible errors from "restart tor" command.
        '''
        try:
            argv = privilege.command('acw-tor-control-restart')
        except privilege.NoPrivilegeMethod:
            ## Nothing can restart Tor on this system. Report it the same way a
            ## failed restart is reported, rather than letting the exception
            ## escape and abort the widget with a traceback.
            box = QMessageBox()
            box.setIcon(QMessageBox.Critical)
            box.setWindowTitle('Restart Tor')
            box.setText('Cannot restart Tor: no privilege escalation method '
                        '(privleap, pkexec or passwordless sudo) is '
                        'available.')
            box.exec_()
            sys.exit(1)

        command = Popen(argv, stdout=PIPE, stderr=PIPE)
        stdout, stderr = command.communicate()

        std_err = stderr.decode()
        command_success = command.returncode == 0

        if not command_success:
            box = QMessageBox()
            box.setIcon(QMessageBox.Critical)
            box.setWindowTitle('restart-tor - Error')
            text = (
                "Command '" + ' '.join(argv) + "' failed.\n\n"
                'stderr: ' + std_err
            )
            print('ERROR: ' + text)
            box.setText(text)
            box.exec_()
            sys.exit(1)

        self.bootstrap_thread = tor_bootstrap.TorBootstrap(self)
        self.bootstrap_thread.signal.connect(self.update_bootstrap)
        self.bootstrap_thread.finished.connect(self.close)
        self.bootstrap_thread.start()

        self.show()
        self.center()

def signal_handler(sig, frame):
    sys.exit(128 + sig)

def main():
    if os.geteuid() == 0:
        print('restart_tor.py: ERROR: Do not run with sudo / as root!')
        sys.exit(1)
    app = QApplication(sys.argv)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timer = QtCore.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    restart_tor = RestartTor()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
