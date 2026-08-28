#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import os, re, fcntl

from . import privilege

if os.path.exists('/usr/share/anon-gw-base-files/gateway'):
    whonix = True
else:
    whonix = False

## The torrc drop-in directory is distro-dependent -- and it MUST be, because
## Tor is confined and can only read its config from certain locations:
##   * Whonix: /usr/local/etc/torrc.d -- where the anon-gw config already
##     chains the %include and Tor is permitted to read.
##   * plain Debian / Kicksecure: /etc/tor/torrc.d -- Debian ships an AppArmor
##     profile (system_tor) that lets Tor read /etc/tor/** but NOT
##     /usr/local/**, so a drop-in under /usr/local makes tor@default fail to
##     start ("Error reading included configuration file or directory"). Do NOT
##     unify these onto /usr/local: it is AppArmor-unreadable on Debian.
## tor-config-sane adds the matching %include (stock /etc/tor/torrc has none;
## Debian bug #866187). The privileged bash helpers (tor-config-sane,
## acw-write-torrc) derive the same distro-aware path from the Whonix marker,
## since the escalators (leaprun/pkexec/sudo) do not forward this value.
if whonix:
    torrc_dir = '/usr/local/etc/torrc.d'
else:
    torrc_dir = '/etc/tor/torrc.d'
torrc_file_path = torrc_dir + '/40_tor_control_panel.conf'
torrc_user_file_path = torrc_dir + '/50_user.conf'
acw_comm_file_path = '/run/anon-connection-wizard/tor.conf'

## torrc options whose value is a credential. This module prints torrc content
## to stdout for troubleshooting, and stdout of a GUI app started from a
## desktop file is captured by the session journal, so the value has to be
## stripped before it is printed.
credential_options = [
    'Socks5ProxyUsername',
    'Socks5ProxyPassword',
    'HTTPProxyAuthenticator',
    'HTTPSProxyAuthenticator',
    'HashedControlPassword',
]

## Space and tab only, never '\s': '\s' matches a newline, so an option left
## without a value ('Socks5ProxyPassword\n') would consume the line break and
## redact the NEXT directive instead, silently hiding it from the
## troubleshooting output.
credential_line_regex = re.compile(
    r'^([ \t]*(?:' + '|'.join(credential_options) + r')[ \t]+).*$',
    re.IGNORECASE | re.MULTILINE)


def redact_credentials(content):
    """Replace the value of any credential-bearing torrc option.

    Keeps the option name so the log still shows that the option was set,
    which is what the troubleshooting output is for.
    """
    return credential_line_regex.sub(r'\1[REDACTED]', content)


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
        with open(torrc_file_path, 'r', encoding='utf-8') as torrc_file:
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
        ## Present but carrying no active DisableNetwork directive is the same
        ## situation as the missing-file branch above: Tor applies its own
        ## default of DisableNetwork 0. Returning None here reported
        ## 'tor_disabled' for a Tor that is running with the network enabled,
        ## which made refresh() label the toggle 'Enable network'.
        return True

    if tor_enabled_check():
        return 'tor_enabled'
    else:
        return 'tor_disabled'

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
        with open(torrc_file_path, 'r', encoding='utf-8') as torrc_file:
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
    with open(acw_comm_file_path, 'w', encoding='utf-8') as comm_file:
        ## Using flock here prevents another anon-connection-wizard process
        ## from trying to write to the file until acw-write-torrc is finished
        ## processing it.
        fcntl.flock(comm_file, fcntl.LOCK_EX)
        comm_file.write(content)
        ## No need to unlock, acw-write-torrc deletes the original file.

    privilege.check_run('acw-write-torrc')

def user_in_debian_tor_group():
    """True if the current user is a member of the debian-tor group.

    Checks /etc/group (not the running process's groups), because on plain
    Debian the tor control socket + cookie are group-accessible to debian-tor
    and the GUI needs to know whether the account has been granted access --
    even before the user has logged out and back in for it to take effect.
    """
    import grp
    import getpass
    try:
        return getpass.getuser() in grp.getgrnam('debian-tor').gr_mem
    except KeyError:
        return False


def cat(filename):
    """Print the contents of `filename` (debug helper)."""
    print(f"cat filename: '{filename}'")
    if not os.path.exists(filename):
        print(f"File did not exist: '{filename}'")
        return
    with open(filename, 'r', encoding='utf-8') as file:
        content = file.read()
        if not content:
            print(f"File is empty: '{filename}'")
        else:
            print(redact_credentials(content), end='')  # content already has newlines
    print('')

## Debugging: Executing this script directly.
if __name__ == '__main__':
    # Example usage
    print('Enabling...')
    print(set_enabled())
    print('Disabling...')
    print(set_disabled())
    print('Done.')
