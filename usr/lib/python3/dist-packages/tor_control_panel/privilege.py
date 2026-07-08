#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Portable privilege escalation for tor-control-panel.

One place decides HOW a privileged action runs, so the GUI never hard-codes an
escalator. The chain (forum posts #105 / #110 / #123):

  1. privleap's `leaprun` if available (Whonix / Kicksecure with
     user-sysmaint-split). leaprun looks the action up BY NAME in the privleap
     config, so the argv is just `leaprun <action>`.
  2. else `pkexec` (plain Debian, with the polkit policies shipped in the
     tor-control-panel-pkexec package). pkexec needs a real executable PATH, not
     a privleap action name, so each action is mapped to its command here.
  3. else passwordless `sudo` (`sudo --non-interactive <command>`), for a system
     that has neither privleap nor pkexec but a sudoers rule.
  4. else raise -- no escalation method is available.

Every action maps to a fixed, self-validating helper (the same command the
privleap config runs), so the pkexec / sudo path authorizes exactly those
helpers rather than a general-purpose tool.
"""

import shutil
import subprocess


## Canonical action name -> the exact command it runs. Keep in sync with
## etc/privleap/conf.d/tor-control-panel.conf (leaprun resolves the name to that
## same Command=; pkexec / sudo run the command directly).
_ACTION_COMMANDS = {
    'acw-tor-control-restart':
        ['/usr/libexec/anon-connection-wizard/acw-tor-control', 'restart'],
    'acw-tor-control-reload':
        ['/usr/libexec/anon-connection-wizard/acw-tor-control', 'reload'],
    'acw-tor-control-stop':
        ['/usr/libexec/anon-connection-wizard/acw-tor-control', 'stop'],
    'acw-tor-control-status':
        ['/usr/libexec/anon-connection-wizard/acw-tor-control', 'status'],
    'acw-write-torrc':
        ['/usr/libexec/anon-connection-wizard/acw-write-torrc'],
    'tor-config-sane':
        ['/usr/libexec/tor-control-panel/tor-config-sane'],
    'tor-control-panel-read-tor-default-log':
        ['/usr/libexec/tor-control-panel/tcp-read-tor-log'],
    ## Whonix-Gateway only: anon-dns (from anon-gw-anonymizer-config) configures
    ## Whonix-Gateway system DNS. Never invoked on plain Debian, where DNS is
    ## assumed already configured (see edit_etc_resolv_conf).
    'anon-dns-add':
        ['/usr/bin/anon-dns', 'add'],
    'anon-dns-remove':
        ['/usr/bin/anon-dns', 'remove'],
}


class NoPrivilegeMethod(RuntimeError):
    """Raised when no privilege-escalation method (leaprun / pkexec / sudo) is
    available."""


def leaprun_available():
    """True if privleap's leaprun is installed."""
    return shutil.which('leaprun') is not None


def _passwordless_sudo_available(mapped_command):
    """True if sudo can run exactly `mapped_command` without a password prompt.

    Probes the real helper via `sudo --non-interactive --list -- <cmd>`, NOT a
    generic `true`: a sudoers rule scoped with NOPASSWD to the helper path would
    still require a password for `true`, so probing `true` would wrongly disable
    an available sudo fallback.
    """
    if shutil.which('sudo') is None:
        return False
    try:
        return subprocess.call(
            ['sudo', '--non-interactive', '--list', '--'] + list(mapped_command),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except OSError:
        return False


def _mapped_command(action, args):
    command = _ACTION_COMMANDS.get(action)
    if command is None:
        raise KeyError('unknown privileged action: {0!r}'.format(action))
    return command + list(args)


def command(action, *args):
    """Full argv to run `action` (+ args) via the best available escalator.

    Use this when the caller needs its own Popen (e.g. to capture stdout/stderr);
    otherwise use run()/check_run().
    """
    if leaprun_available():
        ## leaprun resolves the action name via the privleap config.
        return ['leaprun', action, *args]
    if shutil.which('pkexec') is not None:
        return ['pkexec'] + _mapped_command(action, args)
    mapped = _mapped_command(action, args)
    if _passwordless_sudo_available(mapped):
        return ['sudo', '--non-interactive'] + mapped
    raise NoPrivilegeMethod(
        'no privilege escalation available for {0!r}: need privleap (leaprun), '
        'pkexec, or passwordless sudo'.format(action))


def run(action, *args):
    """Run privileged `action` (with optional args) and return its exit code."""
    return subprocess.call(command(action, *args))


def check_run(action, *args):
    """Like run(), but raise CalledProcessError on a non-zero exit."""
    subprocess.check_call(command(action, *args))
