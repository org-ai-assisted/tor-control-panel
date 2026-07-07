#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Portable privilege escalation for tor-control-panel.

Per the design discussed by adrelanos and ArrayBolt3 for making the tool work
beyond Whonix (forum thread posts #105 / #110 / #123): use privleap's `leaprun`
when it is available (Whonix / Kicksecure with user-sysmaint-split), otherwise
fall back to `pkexec` (polkit), as the code historically did. This keeps a
single place that decides HOW a privileged action is run, instead of
hard-coding `leaprun` throughout the GUI, so a non-privleap (plain Debian)
system can be supported by only adjusting this module.
"""

import shutil
import subprocess


def leaprun_available():
    """True if privleap's leaprun is installed."""
    return shutil.which('leaprun') is not None


def _prefix():
    if leaprun_available():
        return ['leaprun']
    ## Non-privleap systems: fall back to polkit's pkexec, as before privleap.
    ## The action must resolve to an executable with an installed polkit policy.
    return ['pkexec']


def run(action, *args):
    """Run privileged `action` (with optional args) and return its exit code."""
    return subprocess.call(_prefix() + [action, *args])


def check_run(action, *args):
    """Like run(), but raise CalledProcessError on a non-zero exit."""
    subprocess.check_call(_prefix() + [action, *args])
