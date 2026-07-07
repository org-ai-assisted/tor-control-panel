#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import os
import subprocess
import traceback

if os.path.exists('/usr/share/anon-gw-base-files/gateway'):
    whonix = True
else:
    whonix = False

def repair_torrc():
    if not whonix:
        ## Not implemented for non-Whonix yet.
        return

    try:
        result = subprocess.run(['leaprun', 'tor-config-sane'])
        if result.returncode != 0:
            print("ERROR: leaprun tor-config-sane exit code:", result.returncode)
    except Exception:
        print("tor-config-sane unexpected error:")
        traceback.print_exc()

def main():
    repair_torrc()

if __name__ == "__main__":
    main()
