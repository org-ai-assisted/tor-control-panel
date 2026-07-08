#!/usr/bin/python3 -su

## Copyright (C) 2021 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import os, sys
from subprocess import check_output, STDOUT, call, Popen, PIPE

from . import privilege
## Single source of the Whonix-gateway check (defined in tor_status).
from .tor_status import whonix

def edit_etc_resolv_conf_add():
   if not whonix:
      ## Not implemented for non-Whonix.
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
      ## Not implemented for non-Whonix.
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
