#!/usr/bin/python3 -su

## Copyright (C) 2021 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Point /etc/resolv.conf at the Tor DNS -- a Whonix-Gateway-only concern.

On a Whonix-Gateway the box itself must resolve names through Tor's DNSPort
(via the Qubes/qemu primary DNS), so the privileged anon-dns helper rewrites
/etc/resolv.conf accordingly. On plain Debian / Kicksecure the system resolver
is assumed to already be configured and working, and tor-control-panel does not
touch DNS -- so both functions are deliberate no-ops off Whonix.
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
      p = Popen(command, stdout=PIPE, stderr=PIPE)
      p.communicate()
   except Exception:
      error_msg = "edit-etc-resolv-conf add unexpected error: " + str(sys.exc_info()[0])
      print(error_msg)

def edit_etc_resolv_conf_remove():
   if not whonix:
      ## Whonix-Gateway only; on Debian/Kicksecure DNS is assumed already set up.
      return

   try:
      command = privilege.command('anon-dns-remove')
      p = Popen(command, stdout=PIPE, stderr=PIPE)
      p.communicate()
   except Exception:
      error_msg = "edit-etc-resolv-conf remove unexpected error: " + str(sys.exc_info()[0])
      print(error_msg)

def main():
   edit_etc_resolv_conf_add()

if __name__ == "__main__":
    main()
