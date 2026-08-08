#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import json
from pathlib import Path

from sanitize_string.sanitize_string_lib import sanitize_string

from . import info
from .edit_etc_resolv_conf import edit_etc_resolv_conf_add
## The distro-aware drop-in path is defined once, in tor_status; import it here
## rather than recomputing it, so the two modules can never disagree on where
## the torrc lives (forum post #154: torrc.d is the sustainable target, and the
## GUI -- unlike the package -- may write Tor's config directly).
from .tor_status import (write_to_temp_then_move, torrc_dir,
                         torrc_file_path, torrc_user_file_path)

bridges_default_path = '/usr/share/anon-connection-wizard/bridges_default'

command_useBridges = 'UseBridges 1\n'

bridges_command = ['ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n',
                   'ClientTransportPlugin snowflake exec /usr/bin/snowflake-client\n',
                   'ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy\n']

bridge_types = ['obfs4',
                'snowflake',
                'meek',
                'Custom bridges']

## The bridge types that ship default bridges (i.e. everything but the
## user-supplied 'Custom bridges'); the canonical source for both GUIs.
default_bridge_types = ['obfs4',
                        'snowflake',
                        'meek']

proxy_torrc = ['HTTPSProxy',
               'Socks4Proxy',
               'Socks5Proxy']

proxies = ['HTTP / HTTPS',
           'SOCKS4',
           'SOCKS5']

proxy_auth = ['HTTPSProxyAuthenticator',
              'Socks5ProxyUsername',
              'Socks5ProxyPassword']


def torrc_path():
    return torrc_file_path

def user_path():
    return torrc_user_file_path

def torrc_include_directive():
    '''The %include line the top-level torrc must contain for Tor to actually
    read our drop-in directory.

    Writing a drop-in is pointless if the main torrc does not pull in torrc_dir:
    on plain Debian the stock /etc/tor/torrc has no such %include (Debian bug
    #866187), and Tor is started with `-f /etc/tor/torrc`, so a drop-in we write
    is silently IGNORED. On Whonix the anon-gw config supplies the include.
    '''
    return '%include ' + torrc_dir + '/*.conf'

def main_torrc_includes_dropin(main_torrc_text):
    '''True if `main_torrc_text` (the top-level torrc Tor is launched with)
    has an active %include that pulls in our drop-in directory, so the
    directives we write there are actually applied rather than ignored.

    A commented-out %include does not count. The %include target may name the
    directory, a glob inside it, or a specific file in it -- any of these means
    Tor reads torrc_dir.
    '''
    for line in main_torrc_text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        parts = stripped.split(None, 1)
        if parts and parts[0] == '%include' and len(parts) == 2:
            if torrc_dir in parts[1]:
                return True
    return False

def read_custom_bridge_lines(torrc_file):
    '''Return the user's custom Bridge lines from `torrc_file` (the
    '# Custom bridges are used' block), with the leading 'Bridge ' stripped and
    each line sanitized.

    Shared by both GUIs' "retrieve custom bridges" step. The torrc is untrusted
    (the lines are user-pasted, round-trip through the file, and could be
    tampered with) and they are appended into a rich-text QTextEdit, so strip
    markup / control characters first -- the same treatment refresh_logs already
    gives the torrc it displays.
    '''
    path = Path(torrc_file)
    if not path.exists():
        return []
    contents = path.read_text(encoding='utf-8')
    if '# Custom' not in contents:
        return []
    bridge_lines = []
    for line in contents.split('\n'):
        ## Match the exact 'Bridge' directive token, not the prefix, so
        ## unrelated directives that merely start with 'Bridge' (BridgeRelay,
        ## BridgeDistribution, ...) are not mistaken for a custom bridge and
        ## surfaced -- sliced and sanitized -- to the user.
        tokens = line.strip().split(None, 1)
        if len(tokens) == 2 and tokens[0] == 'Bridge':
            bridge_lines.append(sanitize_string(tokens[1].strip()))
    return bridge_lines

def gen_torrc(args):
    bridge_type = str(args[0]) if len(args) > 0 else 'None'
    custom_bridges = str(args[1]) if len(args) > 1 else 'error-unknown-bridge-type'
    proxy_type = str(args[2]) if len(args) > 2 else 'None'

    torrc_content = ['%s# %s\n' % (info.torrc_text(), torrc_user_file_path), 'DisableNetwork 0\n']

    if bridge_type != 'None':
        if bridge_type in bridge_types:
            torrc_content.append(command_useBridges)
            torrc_content.append(bridges_command[bridge_types.index(bridge_type)])
            with open(bridges_default_path, encoding='utf-8') as bridges_file:
                bridges = json.loads(bridges_file.read())
            for bridge in bridges['bridges'][bridge_type]:
                if bridge.strip():
                    torrc_content.append('{0}\n'.format(bridge))

    ## Transports found in the custom bridges (used below to decide whether the
    ## meek/snowflake DNS workaround is needed); stays empty for non-custom.
    emitted_plugins = set()
    if custom_bridges != 'None':
        torrc_content.append('# Custom bridges are used\n')
        torrc_content.append(command_useBridges)
        ## Emit the matching ClientTransportPlugin line for every pluggable
        ## transport present in the custom bridges. A Bridge line's first token
        ## is the transport name ('obfs4', 'snowflake', 'meek_lite'); a plain
        ## vanilla bridge (IP:port first) needs no plugin. Lines may mix
        ## transports, so scan them all and de-duplicate the plugin lines.
        transport_plugins = {
            'obfs4': bridges_command[0],
            'snowflake': bridges_command[1],
            'meek_lite': bridges_command[2],
        }
        for bridge_line in custom_bridges.split('\n'):
            tokens = bridge_line.split()
            transport = tokens[0] if tokens else ''
            if transport in transport_plugins and transport not in emitted_plugins:
                torrc_content.append(transport_plugins[transport])
                emitted_plugins.add(transport)
        for bridge in custom_bridges.split('\n'):
            if bridge.strip():
                torrc_content.append('Bridge {0}\n'.format(bridge))

    # Required for meek and snowflake only (Whonix; no-op elsewhere).
    # https://forums.whonix.org/t/censorship-circumvention-tor-pluggable-transports/2601/9
    # Trigger for the default meek/snowflake bridge types AND for custom bridges
    # whose transports are meek_lite / snowflake -- otherwise those custom
    # bridges miss the DNS workaround and can fail to connect.
    if (bridge_type.startswith('meek') or bridge_type.startswith('snowflake')
            or emitted_plugins & {'meek_lite', 'snowflake'}):
        edit_etc_resolv_conf_add()

    if proxy_type != 'None' and len(args) >= 7:
        proxy_ip = str(args[3])
        proxy_port = str(args[4])
        proxy_username = str(args[5])
        proxy_password = str(args[6])

        if proxy_type in proxies and proxy_ip and proxy_port:
            ## Bracket an IPv6 literal so the '<addr>:<port>' form stays
            ## unambiguous (Tor's *Proxy directives accept [ipv6]:port).
            proxy_addr = '[{0}]'.format(proxy_ip) if ':' in proxy_ip else proxy_ip
            torrc_content.append('{0} {1}:{2}\n'.format(proxy_torrc[proxies.index(proxy_type)],
                                                        proxy_addr, proxy_port))
            if proxy_username:
                if proxy_type == proxies[0]:
                    torrc_content.append('{0} {1}:{2}\n'.format(proxy_auth[0], proxy_username,
                                                                proxy_password))
                if proxy_type == proxies[2]:
                    torrc_content.append('{0} {1}\n'.format(proxy_auth[1], proxy_username))
                    if proxy_password:
                        torrc_content.append('{0} {1}\n'.format(proxy_auth[2], proxy_password))

    final_torrc_content = ''.join(torrc_content)
    write_to_temp_then_move(final_torrc_content)

def parse_torrc():
    ## On a plain Debian / Kicksecure system the tor-control-panel torrc may
    ## not exist yet (no Whonix drop-in). Treat an absent file as "no
    ## configuration" (defaults) rather than crashing the whole GUI.
    torrc_file_path_obj = Path(torrc_file_path)
    if not torrc_file_path_obj.exists():
        return ('None', 'None', '', '', '', '')
    torrc_file_contents = torrc_file_path_obj.read_text(encoding='utf-8')
    torrc_file_lines = torrc_file_contents.split('\n')
    ## Detect features from active (non-comment) directives only; a commented
    ## '# HTTPSProxy ...' or '# UseBridges' must not be mistaken for a setting
    ## in effect (otherwise proxy_type would come back '' instead of 'None').
    active_text = '\n'.join(line for line in torrc_file_lines
                            if not line.strip().startswith('#'))
    use_bridge = 'UseBridges' in active_text
    ## The custom-bridges marker is deliberately a comment we write ourselves.
    use_custom_bridges = '# Custom bridges are used' in torrc_file_contents
    use_proxy = 'Proxy' in active_text

    ## Default to 'None' so use_bridge with no parseable Bridge line (and not
    ## custom) does not leave bridge_type as an empty string.
    bridge_type = 'None'

    if use_bridge:
        for line in torrc_file_lines:
            if line.strip().startswith('#'):
                continue

            if line.strip().startswith('Bridge'):
                line = line.split()
                # The bridge name is 'meek_lite', the bridge type is 'meek'
                if len(line) >= 2:
                    if line[1].startswith('meek_lite'):
                        line[1] = 'meek'
                    bridge_type = line[1]

        ## Custom bridges override any transport guessed from the Bridge lines;
        ## decided once, not re-set on every loop iteration.
        if use_custom_bridges:
            bridge_type = 'Custom bridges'

    if use_proxy:
        proxy_type = proxy_ip = proxy_port = proxy_username = proxy_password = ''
        for line in torrc_file_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            key, value = parts[0], parts[1]

            if key in proxy_torrc:
                proxy_type = proxies[proxy_torrc.index(key)]
                if value.startswith('[') and ']' in value:
                    ## Bracketed IPv6 literal: [addr]:port
                    end = value.rfind(']')
                    proxy_ip = value[1:end]
                    rest = value[end + 1:]
                    proxy_port = rest[1:] if rest.startswith(':') else ''
                elif ':' in value:
                    ## ':' guaranteed present, so rsplit yields exactly two.
                    proxy_ip, proxy_port = value.rsplit(':', 1)
                continue

            if key == proxy_auth[0]:  # HTTPSProxyAuthenticator
                if ':' in value:
                    ## ':' guaranteed present, so split yields exactly two.
                    proxy_username, proxy_password = value.split(':', 1)
                continue

            if key == proxy_auth[1]:  # Socks5ProxyUsername
                proxy_username = value
                continue

            if key == proxy_auth[2]:  # Socks5ProxyPassword
                proxy_password = value
                continue

    else:
        proxy_type = 'None'
        proxy_ip = ''
        proxy_port = ''
        proxy_username = ''
        proxy_password = ''

    return (bridge_type, proxy_type, proxy_ip, proxy_port, proxy_username, proxy_password)
