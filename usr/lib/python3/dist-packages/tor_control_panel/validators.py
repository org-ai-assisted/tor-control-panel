#!/usr/bin/python3 -Bsu

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
    """True if `port` is an integer in the 1..65535 range.

    Requires a clean decimal string. int() alone also accepts '1_0', '+80',
    ' 80', and non-ASCII digits (fullwidth forms); any of those would be
    written into the torrc verbatim by gen_torrc and rejected by Tor, so reject
    them here.
    """
    port_text = str(port).strip()
    if not re.fullmatch(r'[0-9]{1,5}', port_text):
        return False
    return 1 <= int(port_text) <= 65535


def valid_proxy_credential(value):
    """True if `value` is safe to write as a proxy username/password value.

    An empty value means "no credential" and is accepted; the caller decides
    whether one is required. A non-empty credential must carry no control
    character -- a line break would end the torrc directive and let the value
    inject an arbitrary one (a pasted hostile SOCKS password
    'x\\nDisableNetwork 1'), and no other control byte belongs in a SOCKS/HTTP
    credential -- and must stay within Tor's 1..255-byte limit. Spaces and
    ordinary Unicode are allowed: Tor reads the value as the rest of the line.
    """
    if value is None:
        return False
    value = str(value)
    if value == '':
        return True
    if len(value.encode('utf-8')) > 255:
        return False
    return not any(ord(character) < 0x20 or 0x7f <= ord(character) <= 0x9f
                   for character in value)


def valid_custom_bridges(text):
    """True if `text` looks like pasted custom bridges: an obfs4 line, or a
    plain address:port (contains both '.' and ':'). Shared by both GUIs."""
    return text.startswith('obfs4') or (('.' in text) and (':' in text))
