#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared input validators for tor-control-panel and anon-connection-wizard, so
the proxy address/port checks live in one place instead of being duplicated in
both GUIs.
"""

import socket


def valid_ip(address):
    """True if `address` resolves as an IPv4 or IPv6 address / host."""
    try:
        ## getaddrinfo (unlike gethostbyname) also resolves IPv6 addresses.
        socket.getaddrinfo(address, None)
        return True
    except OSError:
        return False


def valid_port(port):
    """True if `port` is an integer in the 1..65535 range."""
    try:
        return 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        return False
