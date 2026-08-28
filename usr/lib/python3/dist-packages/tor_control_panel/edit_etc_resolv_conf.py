#!/usr/bin/python3 -su

## Copyright (C) 2021 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Configure Whonix-Gateway system DNS -- a Whonix-Gateway-only concern.

The privileged anon-dns helper adjusts /etc/resolv.conf on a Whonix-Gateway; see
https://www.whonix.org/wiki/Whonix-Gateway_System_DNS

On plain Debian / Kicksecure the system resolver is assumed already configured,
so both functions are deliberate no-ops off Whonix.
"""

import sys
from subprocess import Popen, PIPE

from . import privilege
## Single source of the Whonix-gateway check (defined in tor_status).
from .tor_status import whonix

def edit_etc_resolv_conf_add():
   if not whonix:
      ## Whonix-Gateway only; on Debian/Kicksecure DNS is assumed already set up.
      return

   try:
      command = privilege.command('anon-dns-add')
      proc = Popen(command, stdout=PIPE, stderr=PIPE)
      proc.communicate()
   except Exception:
      error_msg = 'edit-etc-resolv-conf add unexpected error: ' + str(sys.exc_info()[0])
      print(error_msg)

def edit_etc_resolv_conf_remove():
   if not whonix:
      ## Whonix-Gateway only; on Debian/Kicksecure DNS is assumed already set up.
      return

   try:
      command = privilege.command('anon-dns-remove')
      proc = Popen(command, stdout=PIPE, stderr=PIPE)
      proc.communicate()
   except Exception:
      error_msg = 'edit-etc-resolv-conf remove unexpected error: ' + str(sys.exc_info()[0])
      print(error_msg)

def main():
   edit_etc_resolv_conf_add()

if __name__ == '__main__':
    main()
