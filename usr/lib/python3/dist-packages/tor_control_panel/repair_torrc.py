#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import subprocess
import traceback

from . import privilege

def repair_torrc():
    ## tor-config-sane is distro-agnostic: on plain Debian it adds the %include
    ## and control socket, on Whonix it just ensures the drop-in directory. So
    ## it must run on every distro, not only Whonix.
    try:
        command = privilege.command('tor-config-sane')
        result = subprocess.run(command)
        if result.returncode != 0:
            print('ERROR:', ' '.join(command), 'exit code:', result.returncode)
    except Exception:
        print('tor-config-sane unexpected error:')
        traceback.print_exc()

def main():
    repair_torrc()

if __name__ == '__main__':
    main()
