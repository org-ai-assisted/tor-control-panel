#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import os, fcntl

from . import privilege

if os.path.exists('/usr/share/anon-gw-base-files/gateway'):
    whonix = True
else:
    whonix = False

## The torrc drop-in lives in /usr/local/etc/torrc.d on EVERY distro (the
## single definition; torrc_gen imports these). On Whonix this is where the
## anon-gw config already %includes; on plain Debian / Kicksecure tor-config-sane
## makes Tor read it (adds the %include; stock /etc/tor/torrc has none, Debian
## bug #866187). Using one path everywhere keeps the Python and the privileged
## bash helpers (tor-config-sane, which adds the %include, and acw-write-torrc,
## which stages the drop-in) in agreement instead of split-brained.
torrc_dir = '/usr/local/etc/torrc.d'
torrc_file_path = torrc_dir + '/40_tor_control_panel.conf'
torrc_user_file_path = torrc_dir + '/50_user.conf'
acw_comm_file_path = '/run/anon-connection-wizard/tor.conf'


def tor_status():
    """Return 'tor_enabled' or 'tor_disabled' from the torrc DisableNetwork setting."""
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
        with open(torrc_file_path, 'r', encoding="utf-8") as torrc_file:
            for line in torrc_file:
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
        return "tor_enabled"
    else:
        return "tor_disabled"

## Unlike tor_status(), which only shows the current state of the torrc,
## set_enabled() and set_disabled() also repair a missing torrc / DisableNetwork
## line, since when they are called we really want Tor to work. set_enabled()
## returns a (error-type string, error-code int) tuple.
##
## set_enabled() guarantees: the torrc exists, its final DisableNetwork value is
## 0, and Tor uses DisableNetwork 0.
def _write_disable_network(value):
    '''Rewrite the torrc so the DisableNetwork directive equals `value`.

    Only the real directive (first token on a non-comment line) is changed, so
    a commented-out or partial 'DisableNetwork' occurrence is left alone; the
    directive is appended if absent. The result is staged via the privileged
    acw-write-torrc helper (write_to_temp_then_move). Shared by set_enabled()
    and set_disabled().
    '''
    ## On plain Debian / Kicksecure the drop-in may not exist yet; set_enabled()
    ## / set_disabled() are documented to repair a missing torrc, so treat an
    ## absent file as empty and create it rather than raising FileNotFoundError.
    if os.path.exists(torrc_file_path):
        with open(torrc_file_path, 'r', encoding="utf-8") as torrc_file:
            lines = torrc_file.read().split('\n')
    else:
        lines = []

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

    tor_status_code = privilege.run('acw-tor-control-restart')
    if tor_status_code != 0:
        return 'cannot_connect', tor_status_code

    ## we have to reload to open /run/tor/control and create /run/tor/control.authcookie
    privilege.run('acw-tor-control-reload')

    tor_status_code = privilege.run('acw-tor-control-status')
    if tor_status_code != 0:
        return 'cannot_connect', tor_status_code

    return 'tor_enabled', tor_status_code

## set_disabled() guarantees: the torrc exists, its final DisableNetwork value
## is 1, and Tor uses DisableNetwork 1.
def set_disabled():
    _write_disable_network('1')

    privilege.run('acw-tor-control-stop')

    return 'tor_disabled'

def write_to_temp_then_move(content):
    with open(acw_comm_file_path, 'w', encoding="utf-8") as comm_file:
        ## Using flock here prevents another anon-connection-wizard process
        ## from trying to write to the file until acw-write-torrc is finished
        ## processing it.
        fcntl.flock(comm_file, fcntl.LOCK_EX)
        comm_file.write(content)
        ## No need to unlock, acw-write-torrc deletes the original file.

    privilege.check_run('acw-write-torrc')

def cat(filename):
    """Print the contents of `filename` (debug helper)."""
    print(f"cat filename: '{filename}'")
    if not os.path.exists(filename):
        print(f"File did not exist: '{filename}'")
        return
    with open(filename, 'r', encoding="utf-8") as file:
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
