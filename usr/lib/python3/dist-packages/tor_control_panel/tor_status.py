#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import os, subprocess, fcntl

if os.path.exists('/usr/share/anon-gw-base-files/gateway'):
    whonix=True
else:
    whonix=False

## TODO: code duplication
## Should use same variable as in anon_connection_wizard.py.
torrc_file_path = '/usr/local/etc/torrc.d/40_tor_control_panel.conf'
acw_comm_file_path = '/run/anon-connection-wizard/tor.conf'


def tor_status():
    print("tor_status was called.")

    # output = self.tor_enabled_check()  #subprocess.check_output('/usr/libexec/helper-scripts/tor_enabled_check')
    # output = output.decode("UTF-8").strip()

    def tor_enabled_check():
        ## Match the DisableNetwork directive itself (first token on a
        ## non-comment line), not any substring -- a commented-out or partial
        ## occurrence must not be mistaken for the active setting.
        ##
        ## On a plain Debian / Kicksecure system the torrc may be absent; Tor's
        ## own default is DisableNetwork 0 (enabled), so report enabled rather
        ## than crashing.
        if not os.path.exists(torrc_file_path):
            return True
        with open(torrc_file_path, 'r', encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                parts = stripped.split()
                if len(parts) >= 2 and parts[0] == 'DisableNetwork':
                    if parts[1] == '1':
                        return False
                    if parts[1] == '0':
                        return True
        return None

    if tor_enabled_check():
        print("tor_status status: tor_enabled")
        return "tor_enabled"
    else:
        print("tor_status status: tor_disabled")
        return "tor_disabled"

'''Unlike tor_status() function which only shows the current state of the anon_connection_wizard.conf,
set_enabled() and set_disabled() function will try to repair the missing torrc or DisableNetwork line.
This makes sense because when we call set_enabled() or set_disabled() we really want Tor to work.

set_enabled() will return a tuple with two value: a string of error type and an int of error code.
'''

'''set_enabled() is specified as follows:
set_enabled() will:
1. guarantee the existence of 40_tor_control_panel.conf
2. guarantee the final value of DisableNetwork is 0 in the file
3. guarantee Tor uses DisableNetwork 0
'''
def _write_disable_network(value):
    '''Rewrite the torrc so the DisableNetwork directive equals `value`.

    Only the real directive (first token on a non-comment line) is changed, so
    a commented-out or partial 'DisableNetwork' occurrence is left alone; the
    directive is appended if absent. The result is staged via the privileged
    acw-write-torrc helper (write_to_temp_then_move). Shared by set_enabled()
    and set_disabled().
    '''
    with open(torrc_file_path, 'r', encoding="utf-8") as f:
        lines = f.read().split('\n')

    found = False
    for index, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue
        if line.strip().split()[:1] == ['DisableNetwork']:
            ## Normalize every active directive (a duplicated torrc could carry
            ## more than one), not just the first, so no conflicting value is
            ## left behind.
            lines[index] = 'DisableNetwork ' + value
            found = True
    if not found:
        lines.append('DisableNetwork ' + value)

    write_to_temp_then_move('\n'.join(lines))


def set_enabled():
    _write_disable_network('0')

    command = 'leaprun acw-tor-control-restart'
    tor_status_code = subprocess.call(command, shell=True)

    if tor_status_code != 0:
        return 'cannot_connect', tor_status_code

    ## we have to reload to open /run/tor/control and create /run/tor/control.authcookie
    command = 'leaprun acw-tor-control-reload'
    subprocess.call(command, shell=True)

    command = 'leaprun acw-tor-control-status'
    tor_status_code = subprocess.call(command, shell=True)

    if tor_status_code != 0:
        return 'cannot_connect', tor_status_code

    return 'tor_enabled', tor_status_code

'''set_disabled() is specified as follows:
set_disabled() will:
1. guarantee the existence of 40_tor_control_panel.conf
2. guarantee the final value of DisableNetwork is 1 in the file
3. guarantee Tor uses DisableNetwork 1
'''
def set_disabled():
    _write_disable_network('1')

    command = 'leaprun acw-tor-control-stop'
    subprocess.call(command, shell=True)

    return 'tor_disabled'

def write_to_temp_then_move(content):
    print("before:")
    cat(torrc_file_path)
    cat(acw_comm_file_path)
    print(f"content to write: '{content}'")

    with open(acw_comm_file_path, 'w') as comm_file:
        ## Using flock here prevents another anon-connection-wizard process
        ## from trying to write to the file until acw-write-torrc is finished
        ## processing it.
        fcntl.flock(comm_file, fcntl.LOCK_EX)
        comm_file.write(content)
        ## No need to unlock, acw-write-torrc deletes the original file.

    print("after 1:")
    cat(acw_comm_file_path)

    command = ['leaprun', 'acw-write-torrc']
    print("tor_status.py: executing:", ' '.join(command))
    subprocess.check_call(command)

    print("after 2:")

    cat(torrc_file_path)

def cat(filename):
    print(f"cat filename: '{filename}'")
    if not os.path.exists(filename):
        print(f"File did not exist: '{filename}'")
        return
    with open(filename, 'r') as file:
        content = file.read()
        if not content:
            print(f"File is empty: '{filename}'")
        else:
            print(content, end='')  # content already has newlines
    print("")

## Debugging: Executing this script directly.
if __name__ == "__main__":
    # Example usage
    print("Enabling...")
    print(set_enabled())
    print("Disabling...")
    print(set_disabled())
    print("Done.")
