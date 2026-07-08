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
    ## Reject empty/blank input explicitly: getaddrinfo('') is platform-
    ## dependent (may return loopback rather than raising), which would let an
    ## empty proxy/bridge host slip through as "valid".
    if not address or not str(address).strip():
        return False
    try:
        ## getaddrinfo (unlike gethostbyname) also resolves IPv6 addresses.
        socket.getaddrinfo(address, None)
        return True
    except (OSError, UnicodeError):
        ## OSError: not resolvable. UnicodeError: getaddrinfo's IDNA encoder
        ## raises (not OSError) on e.g. an over-long hostname label -- a hostile
        ## proxy/bridge host must be rejected, not crash the validator.
        return False


def valid_port(port):
    """True if `port` is an integer in the 1..65535 range."""
    try:
        return 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        return False


def valid_custom_bridges(text):
    """True if `text` looks like pasted custom bridges: an obfs4 line, or a
    plain address:port (contains both '.' and ':'). Shared by both GUIs."""
    return text.startswith('obfs4') or (('.' in text) and (':' in text))
