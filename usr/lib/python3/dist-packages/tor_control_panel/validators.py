#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared input validators for tor-control-panel and anon-connection-wizard, so
the proxy address/port checks live in one place instead of being duplicated in
both GUIs.
"""

import ipaddress
import re

## A DNS hostname: dot-separated labels of alphanumerics and hyphens, no label
## starting or ending with a hyphen, each label 1..63 characters, 253 overall.
_HOSTNAME_LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_HOSTNAME_REGEX = re.compile(
    r'^' + _HOSTNAME_LABEL + r'(?:\.' + _HOSTNAME_LABEL + r')*\.?$')


def valid_ip(address):
    """True if `address` is a syntactically valid IP literal or hostname.

    Deliberately SYNTACTIC -- it must not resolve. This runs on the GUI thread
    from both front-ends, and resolving had two consequences: a non-resolving
    host froze the window until the resolver timed out, and the lookup went to
    the system resolver before Tor was configured, disclosing a user-entered
    proxy/bridge hostname outside Tor. For a proxy address the user typed, the
    only thing worth checking here is the shape; whether it resolves is Tor's
    problem, over Tor.
    """
    ## Reject empty/blank input explicitly, so a blank proxy/bridge host cannot
    ## slip through as "valid".
    if not address or not str(address).strip():
        return False
    address = str(address).strip()

    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        pass

    ## Accept a bracketed IPv6 literal ('[::1]'), the form a user may paste
    ## from a URL.
    if address.startswith('[') and address.endswith(']'):
        try:
            ipaddress.ip_address(address[1:-1])
            return True
        except ValueError:
            return False

    if len(address) > 253:
        return False
    return bool(_HOSTNAME_REGEX.match(address))


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
