#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import subprocess
import traceback

from . import privilege
## Single source of the Whonix-gateway check (defined in tor_status).
from .tor_status import whonix

def repair_torrc():
    if not whonix:
        ## Not implemented for non-Whonix yet.
        return

    try:
        command = privilege.command('tor-config-sane')
        result = subprocess.run(command)
        if result.returncode != 0:
            print("ERROR:", ' '.join(command), "exit code:", result.returncode)
    except Exception:
        print("tor-config-sane unexpected error:")
        traceback.print_exc()

def main():
    repair_torrc()

if __name__ == "__main__":
    main()
