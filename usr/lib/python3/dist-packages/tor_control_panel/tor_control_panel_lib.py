#!/usr/bin/python3 -Bsu

## Copyright (c) 2018 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, global-statement

"""
Non-Qt Components that are shared between Tor Control Panel and Anon Connection
Wizard. Can be used by other applications that need to interact with Tor for
some reason.
"""

import copy
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

whonix_gw_flag_file: Path = Path("/usr/share/anon-gw-base-files/gateway")

tcpl_priv_executor_map: dict[str, dict[str, list[str]]] = {
    "/usr/bin/leaprun": {
        "tor-config-sane": ["tor-config-sane"],
        "tcp-tor-control-restart": ["tcp-tor-control-restart"],
        "tcp-tor-control-stop": ["tcp-tor-control-stop"],
        "tcp-write-torrc": ["tcp-write-torrc"],
        "tor-control-panel-read-tor-default-log": [
            "tor-control-panel-read-tor-default-log"
        ],
        "anon-dns-add": ["anon-dns-add"],
        "anon-dns-remove": ["anon-dns-remove"],
    },
    "/usr/bin/pkexec": {
        "tor-config-sane": [
            "/usr/libexec/anon-gw-anonymizer-config/tor-config-sane"
        ],
        "tcp-tor-control-restart": [
            "/usr/libexec/tor-control-panel/tcp-tor-control",
            "restart",
        ],
        "tcp-tor-control-stop": [
            "/usr/libexec/tor-control-panel/tcp-tor-control",
            "stop",
        ],
        "tcp-write-torrc": ["/usr/libexec/tor-control-panel/tcp-write-torrc"],
        "tor-control-panel-read-tor-default-log": [
            "journalctl",
            "-n",
            "200",
            "-u",
            "tor@default.service",
        ],
        "anon-dns-add": ["/usr/bin/anon-dns", "add"],
        "anon-dns-remove": ["/usr/bin/anon-dns", "remove"],
    },
    ## Maybe if some users want sudo support?
    # "/usr/bin/sudo": { ... },
}
tcpl_priv_executor: str | None = None
tcpl_torrc_dir: Path = Path("/usr/local/etc/torrc.d")
tcpl_torrc_file: Path = Path(tcpl_torrc_dir, "40_tor_control_panel.conf")
tcpl_torrc_comm_fifo: Path = Path("/run/tor-control-panel/tcp-write-torrc.fifo")
tcpl_system_path: Path = Path(
    "/usr/lib/python3/dist-packages/tor_control_panel_lib.py"
)
tcpl_bridges_default_path: Path
if Path(__file__).resolve() == tcpl_system_path:
    tcpl_bridges_default_path = Path(
        "/usr/share/tor-control-panel/bridges_default"
    )
else:
    tcpl_bridges_default_path = Path(
        Path(__file__).parent.parent.parent.parent.parent,
        "share/tor-control-panel/bridges_default",
    )


tcpl_bridge_type_none_str: str = "None"
tcpl_proxy_type_none_str: str = "None"
tcpl_bridge_type_custom_str: str = "Custom bridges"
## These must be strings as they are displayed in the UI as well as used
## internally. The first item of both these lists MUST be "None" and they both
## MUST contain more than one item. The last item of the bridge type list MUST
## be "Custom bridges".
tcpl_bridge_type_list: list[str] = [
    tcpl_bridge_type_none_str,
    "obfs4",
    "snowflake",
    "meek_lite",
    tcpl_bridge_type_custom_str,
]
tcpl_clearnet_dns_bridge_type_list: list[str] = [
    "snowflake",
    "meek_lite",
]
tcpl_proxy_type_list: list[str] = [
    tcpl_proxy_type_none_str,
    "HTTP / HTTPS",
    "SOCKS4",
    "SOCKS5",
]


tcpl_bridge_transport_dict: dict[str, str] = {
    "obfs4": "exec /usr/bin/obfs4proxy",
    "snowflake": "exec /usr/bin/snowflake-client",
    "meek_lite": "exec /usr/bin/obfs4proxy",
}


tcpl_tor_run_path_str: str = "/run/tor"
tcpl_tor_run_path: Path = Path(tcpl_tor_run_path_str)
tcpl_tor_pid_path: Path = Path(tcpl_tor_run_path, "tor.pid")
tcpl_tor_control_path: Path = Path(tcpl_tor_run_path, "control")
tcpl_tor_auth_path: Path = Path(tcpl_tor_run_path, "control.authcookie")
tcpl_tor_log_path: Path = Path(tcpl_tor_run_path, "log")


class TcplTorStatus(Enum):
    """
    Enum values for the tor status map.
    """

    UNKNOWN = 1
    RUNNING = 2
    STOPPED = 3
    DISABLED = 4
    DISABLED_RUNNING = 5
    ACQUIRING = 6
    NO_CONTROLLER = 7


class TcplTorStatusField(Enum):
    """
    Enum values for the items of the tor status map.
    """

    NAME = 1
    COLOR = 2
    STATUS_TEXT = 3


tcpl_tor_status_map: dict[TcplTorStatus, dict[TcplTorStatusField, str]] = {
    TcplTorStatus.UNKNOWN: {
        TcplTorStatusField.NAME: "unknown",
        TcplTorStatusField.COLOR: "orange",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Tor status unknown.</b></p>
<p>The application is still loading information about Tor status.</p>""",
    },
    TcplTorStatus.RUNNING: {
        TcplTorStatusField.NAME: "running",
        TcplTorStatusField.COLOR: "green",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Tor is running.</b></p>
<p>Everything looks good.</p>""",
    },
    TcplTorStatus.STOPPED: {
        TcplTorStatusField.NAME: "stopped",
        TcplTorStatusField.COLOR: "#AF0000",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Tor is not running.</b></p>
<p>If Tor was stopped intentionally, you can restart it using the [Restart Tor]
button below.</p>
<p>Hints:<br>
In the <b>Logs</b> tab, check the content of torrc and inspect the Tor log and
systemd journal.</p>""",
    },
    TcplTorStatus.DISABLED: {
        TcplTorStatusField.NAME: "disabled",
        TcplTorStatusField.COLOR: "#AF0000",
        TcplTorStatusField.STATUS_TEXT: """<p><b>The network is disabled.</b></p>
<p>A line <i>DisableNetwork 1</i> exists in torrc.</p>
<p>The network can be enabled by clicking:</p>
<p><b>Configure</b> -&gt; check <b>Enable network?</b> -&gt;
<b>Accept</b></p>""",
    },
    TcplTorStatus.DISABLED_RUNNING: {
        TcplTorStatusField.NAME: "disabled_running",
        TcplTorStatusField.COLOR: "orange",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Tor is running but the network
is disabled.</b></p>
<p>A line <i>DisableNetwork 1</i> exists in torrc.</p>
<p>Therefore, you most likely cannot connect to the internet.</p>
<p>The network can be enabled by:</p>
<p><b>Configure</b> -&gt; check <b>Enable network?</b> -&gt;
<b>Accept</b></p>""",
    },
    TcplTorStatus.ACQUIRING: {
        TcplTorStatusField.NAME: "acquiring",
        TcplTorStatusField.COLOR: "orange",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Connecting...</b></p>
<p>Tor is acquiring a connection to the network. Please wait.</p>""",
    },
    TcplTorStatus.NO_CONTROLLER: {
        TcplTorStatusField.NAME: "no_controller",
        TcplTorStatusField.COLOR: "#AF0000",
        TcplTorStatusField.STATUS_TEXT: """<p><b>Tor Controller Not
Constructed</b></p>
<p>This is very likely because you have a <i>DisableNetwork 1</i> line in
torrc.</p>
<p>Remove or comment it out and restart Tor.</p>""",
    },
}


## The only field we could reasonably remove from this is bridge_type_set, and
## then we'd have to recalculate it from bridge_line_list when we need it.
# pylint: disable=too-many-instance-attributes
@dataclass
class TcplTorConfInfo:
    """
    Tor configuration info relevant to Tor Control Panel.
    """

    ## REMINDER: It is possible to configure multiple Tor bridges at once. Both
    ## Tor Control Panel and Anon Connection Wizard can only show one Tor
    ## bridge type, and fall back to displaying "Custom bridges" if multiple
    ## bridge types are configured at once.
    network_enabled: bool | None
    bridges_enabled: bool | None
    bridge_type_set: set[str]
    bridge_line_list: list[str]
    proxy_type: str | None
    proxy_host: str | None
    proxy_port: int | None
    proxy_username: str | None
    proxy_password: str | None


tcpl_blank_tor_conf_info: TcplTorConfInfo = TcplTorConfInfo(
    network_enabled=None,
    bridges_enabled=None,
    bridge_type_set=set(),
    bridge_line_list=[],
    proxy_type=None,
    proxy_host=None,
    proxy_port=None,
    proxy_username=None,
    proxy_password=None,
)


tcpl_torrc_header: str = """\
## This file is generated by and should ONLY be used by tor-control-panel.
## User configuration should go to /usr/local/etc/torrc.d/50_user.conf, not
## here, because:
##   1. This file will be overwritten automatically by Tor Control Panel and
##      Anon Connection Wizard.
##   2. Even a single character change in this file may cause errors.
## However, you may delete this file to undo all Tor configuration set by Tor
## Control Panel and Anon Connection Wizard.
"""


def tcpl_get_privileged_task(task_name: str) -> list[str]:
    """
    Gets the command and arguments to pass to it to run a specified privileged
    command.
    """

    global tcpl_priv_executor

    if tcpl_priv_executor is None:
        for priv_executor_candidate in tcpl_priv_executor_map:
            if os.access(priv_executor_candidate, os.X_OK):
                tcpl_priv_executor = priv_executor_candidate
                break

    if tcpl_priv_executor is None:
        print(
            "ERROR: Could not find a privileged execution tool! Searched for "
            + "tools: "
            + ", ".join(list(tcpl_priv_executor_map.keys())),
            file=sys.stderr,
        )
        sys.exit(1)

    executor_map: dict[str, list[str]] = tcpl_priv_executor_map[
        tcpl_priv_executor
    ]
    if task_name not in executor_map:
        print(
            f"ERROR: Unknown task name '{task_name}' for executor "
            + f"'{tcpl_priv_executor}'!",
            file=sys.stderr,
        )
        sys.exit(1)

    executor_param_list: list[str] = [tcpl_priv_executor]
    executor_param_list.extend(executor_map[task_name])
    return executor_param_list


def tcpl_run_privileged_task_async(task_name: str) -> subprocess.Popen[str]:
    """
    Runs a privileged task asynchronously and returns the running process.
    """

    # pylint: disable=consider-using-with
    run_proc_obj: subprocess.Popen[str] = subprocess.Popen(
        tcpl_get_privileged_task(task_name),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )

    return run_proc_obj


def tcpl_run_privileged_task_sync(
    task_name: str,
) -> subprocess.CompletedProcess[str]:
    """
    Runs a privileged task and returns the result.
    """

    completed_process_obj: subprocess.CompletedProcess[str] = subprocess.run(
        tcpl_get_privileged_task(task_name),
        check=False,
        capture_output=True,
        encoding="utf-8",
    )
    return completed_process_obj


def tcpl_tor_config_sane() -> tuple[bool, str | None]:
    """
    Ensures that Tor is configured in a way that allows these apps to function.
    Will exit the script with an error message if Tor is misconfigured. Returns
    True if the configuration is good, False otherwise. If False is returned,
    the output of the tor-config-sane action will be returned.
    """

    check_proc_result: subprocess.CompletedProcess[str] = (
        tcpl_run_privileged_task_sync("tor-config-sane")
    )
    if check_proc_result.returncode == 0:
        return (True, None)

    error_str: str = check_proc_result.stdout + check_proc_result.stderr
    return (False, error_str)


# pylint: disable=too-many-return-statements, too-many-branches
def tcpl_make_tor_conf_info_sane(
    tor_conf_info: TcplTorConfInfo, proxy_auth_type: str | None = None
) -> TcplTorConfInfo | str:
    """
    Validates tor_conf_info and adjusts its values to be internally consistent
    if needed. If the object has issues that cannot be fixed, returns a string
    describing what is wrong.
    """

    if proxy_auth_type is None:
        proxy_auth_type = tor_conf_info.proxy_type

    out_tor_conf_info: TcplTorConfInfo = copy.deepcopy(tor_conf_info)

    ## If bridges aren't enabled, ignore them.
    if not out_tor_conf_info.bridges_enabled:
        out_tor_conf_info.bridge_type_set.clear()
        out_tor_conf_info.bridge_line_list.clear()

    ## Trim leading and trailing whitespace from the bridge line list.
    for idx, bridge_line in enumerate(out_tor_conf_info.bridge_line_list):
        out_tor_conf_info.bridge_line_list[idx] = bridge_line.strip()

    ## Don't allow unrecognized proxy or bridge types.
    for bridge_type in out_tor_conf_info.bridge_type_set:
        if bridge_type not in tcpl_bridge_type_list[1:-1]:
            return f"Unrecognized bridge type '{bridge_type}' found!"
    if (
        out_tor_conf_info.proxy_type is not None
        and out_tor_conf_info.proxy_type not in tcpl_proxy_type_list[1:]
    ):
        return (
            f"Unrecognized proxy type '{out_tor_conf_info.proxy_type}' found! "
            + "This should never happen, please report this bug!"
        )

    ## Don't allow mismatched proxy_type and proxy_auth_type.
    if (
        out_tor_conf_info.proxy_type is None and proxy_auth_type is not None
    ) or (
        proxy_auth_type is not None
        ## out_tor_conf_info.proxy_type is certainly set if we get this far.
        and out_tor_conf_info.proxy_type != proxy_auth_type
    ):
        return "Mismatch between proxy type and proxy auth type!"

    ## Don't allow mismatched bridge type info.
    for bridge_line in out_tor_conf_info.bridge_line_list:
        bridge_bit_list: list[str] = bridge_line.split(" ")
        assert len(bridge_bit_list) > 1
        if bridge_bit_list[1] not in out_tor_conf_info.bridge_type_set:
            return (
                "Bridge line for unconfigured bridge type "
                + f"'{bridge_bit_list[1]}' found!"
            )

    ## Don't allow a SOCKS5 username without a password, or vice-versa. Also
    ## disallow overly long SOCKS5 credentials.
    if proxy_auth_type == "SOCKS5":
        if (
            tor_conf_info.proxy_username is None
            and tor_conf_info.proxy_password is not None
        ):
            return "SOCKS5 password present without username!"
        if (
            tor_conf_info.proxy_username is not None
            and tor_conf_info.proxy_password is None
        ):
            return "SOCKS5 username present without password!"
        if (
            tor_conf_info.proxy_username is not None
            and not 1 <= len(tor_conf_info.proxy_username) <= 255
        ):
            return "SOCKS5 username too long!"
        if (
            tor_conf_info.proxy_password is not None
            and not 1 <= len(tor_conf_info.proxy_password) <= 255
        ):
            return "SOCKS5 password too long!"

    return out_tor_conf_info


def tcpl_default_port_for_protocol(protocol: str) -> int:
    """
    Returns the default port number for a proxy protocol.
    """

    match protocol:
        case "HTTP / HTTPS":
            return 443
        case "SOCKS4" | "SOCKS5":
            return 1080
        case _:
            raise ValueError(f"Unrecognized protocol '{protocol}'!")


## Config parser, splitting up would make it less readable.
## TODO: Consider making it less painful to change our proxy name strings like
## "HTTP / HTTPS" in the future.
# pylint: disable=too-many-return-statements, too-many-branches, too-many-statements
def tcpl_parse_torrc() -> TcplTorConfInfo | str:
    """
    Parses the Tor Control Panel torrc file. Note that this does NOT include
    information about any other configuration files, including files that may
    override Tor Control Panel's file. If the file is not valid, returns a
    string indicating what is wrong.
    """

    proxy_auth_type: str | None = None
    tor_conf_info: TcplTorConfInfo | str = copy.deepcopy(
        tcpl_blank_tor_conf_info
    )
    assert isinstance(tor_conf_info, TcplTorConfInfo)

    if not tcpl_torrc_file.is_file():
        return (
            f"Cannot read Tor configuration, file {str(tcpl_torrc_file)} does "
            + "not exist!"
        )

    comment_re: re.Pattern[str] = re.compile(r"\s*#")
    torrc_contents: str = tcpl_torrc_file.read_text(encoding="utf-8")
    for torrc_line in torrc_contents.split("\n"):
        if comment_re.match(torrc_line):
            continue
        torrc_line = torrc_line.strip()
        if torrc_line == "":
            continue
        ## Not all torrc options can be safely split this way, some of them use
        ## quoted values. However, all the options we care about can be safely
        ## split this way.
        torrc_bit_list: list[str] = torrc_line.split(" ")

        match torrc_bit_list[0]:
            case "DisableNetwork":
                if len(torrc_bit_list) != 2:
                    return "Invalid number of arguments for DisableNetwork!"
                if tor_conf_info.network_enabled is not None:
                    return "Multiple DisableNetwork lines found!"
                match torrc_bit_list[1]:
                    case "0":
                        tor_conf_info.network_enabled = True
                    case "1":
                        tor_conf_info.network_enabled = False
                    case _:
                        return (
                            "Unexpected DisableNetwork value "
                            + f"'{torrc_bit_list[1]}'!"
                        )
            case "UseBridges":
                if len(torrc_bit_list) != 2:
                    return "Invalid number of arguments for UseBridges!"
                if tor_conf_info.bridges_enabled is not None:
                    return "Multiple UseBridges lines found!"
                match torrc_bit_list[1]:
                    case "0":
                        tor_conf_info.bridges_enabled = False
                    case "1":
                        tor_conf_info.bridges_enabled = True
                    case _:
                        return (
                            "Unexpected UseBridges value "
                            + f"'{torrc_bit_list[1]}'!"
                        )
            case "ClientTransportPlugin":
                if not len(torrc_bit_list) > 1:
                    return "Insufficient arguments for ClientTransportPlugin!"
                tor_conf_info.bridge_type_set.add(torrc_bit_list[1])
            case "Bridge":
                if not len(torrc_bit_list) > 1:
                    return "Insufficient arguments for Bridge line!"
                tor_conf_info.bridge_line_list.append(torrc_line)
            case "HTTPSProxy" | "Socks4Proxy" | "Socks5Proxy":
                if not len(torrc_bit_list) == 2:
                    return (
                        "Invalid number of arguments for "
                        + f"{torrc_bit_list[0]}!"
                    )
                if tor_conf_info.proxy_type is not None:
                    return "Multiple proxies configured!"
                match torrc_bit_list[0]:
                    case "HTTPSProxy":
                        tor_conf_info.proxy_type = "HTTP / HTTPS"
                    case "Socks4Proxy":
                        tor_conf_info.proxy_type = "SOCKS4"
                        ## Suppresses any kind of proxy authentication setting
                        ## being specified since SOCKS4 does not support
                        ## authentication.
                        proxy_auth_type = "SOCKS4"
                    case "Socks5Proxy":
                        tor_conf_info.proxy_type = "SOCKS5"
                tor_conf_info.proxy_port = tcpl_default_port_for_protocol(
                    tor_conf_info.proxy_type
                )
                ## TODO: Consider validating hostnames / IP addresses here.
                host_str: str = torrc_bit_list[1]
                host_bit_list: list[str] = host_str.split(":")
                if len(host_bit_list) > 1:
                    try:
                        tor_conf_info.proxy_port = int(host_bit_list[-1])
                        host_str = ":".join(host_bit_list[:-1])
                    except Exception:
                        ## The bit after the last colon wasn't a port number.
                        ## Might be part of an IPv6 address, so ignore.
                        pass
                tor_conf_info.proxy_host = host_str
            case "HTTPSProxyAuthenticator":
                if not len(torrc_bit_list) == 2:
                    return (
                        "Invalid number of arguments for "
                        + "HTTPSProxyAuthenticator!"
                    )
                if proxy_auth_type is not None:
                    return (
                        "Proxy authentication configured multiple times, or "
                        + "when inappropriate!"
                    )
                auth_bit_list: list[str] = torrc_bit_list[1].split(
                    ":", maxsplit=1
                )
                if len(auth_bit_list) != 2:
                    return (
                        "No password provided to " + "HTTPSProxyAuthenticator!"
                    )
                proxy_auth_type = "HTTP / HTTPS"
                tor_conf_info.proxy_username = auth_bit_list[0]
                tor_conf_info.proxy_password = auth_bit_list[1]
            case "Socks5ProxyUsername":
                if not len(torrc_bit_list) == 2:
                    return (
                        "Invalid number of arguments for "
                        + "Socks5ProxyUsername!"
                    )
                ## We have to tolerate proxy_auth_type already being set to
                ## SOCKS5 since Tor uses separate config options for SOCKS5
                ## username and password.
                if proxy_auth_type is not None and proxy_auth_type != "SOCKS5":
                    return (
                        "Proxy authentication configured multiple times, or "
                        + "when inappropriate!"
                    )
                if tor_conf_info.proxy_username is not None:
                    return "Proxy authentication configured multiple times!"
                proxy_auth_type = "SOCKS5"
                tor_conf_info.proxy_username = torrc_bit_list[1]
            case "Socks5ProxyPassword":
                if not len(torrc_bit_list) == 2:
                    return (
                        "Invalid number of arguments for "
                        + "Socks5ProxyPassword!"
                    )
                if proxy_auth_type is not None and proxy_auth_type != "SOCKS5":
                    return (
                        "Proxy authentication configured multiple times, or "
                        + "when inappropriate!"
                    )
                if tor_conf_info.proxy_password is not None:
                    return "Proxy authentication configured multiple times!"
                proxy_auth_type = "SOCKS5"
                tor_conf_info.proxy_password = torrc_bit_list[1]

    tor_conf_info = tcpl_make_tor_conf_info_sane(tor_conf_info, proxy_auth_type)

    return tor_conf_info


def tcpl_write_torrc(tor_conf_info: TcplTorConfInfo) -> None:
    """
    Writes the Tor Control Panel torrc file. Note that this function assumes
    the data in tor_conf_info has been validated already.
    """

    ## REMINDER: This routine intentionally ignores
    ## tor_conf_info.bridges_enabled. Bridges are considered enabled if there
    ## are bridge lines available.
    ##
    ## REMINDER: This routine intentionally ignores
    ## tor_conf_info.bridge_type_set. Client transport plugins are configured
    ## based on the bridge types specified in the bridge line list.

    torrc_contents: str = f"""{tcpl_torrc_header}
DisableNetwork {"0"
if tor_conf_info.network_enabled
or tor_conf_info.network_enabled is None
else "1"}
UseBridges {"1" if len(tor_conf_info.bridge_line_list) > 0 else "0"}
"""

    seen_bridge_type_list: list[str] = []
    client_transport_block: str = ""
    bridge_block: str = ""
    for bridge_line in tor_conf_info.bridge_line_list:
        bridge_bit_list: list[str] = bridge_line.split(" ", maxsplit=2)
        bridge_type: str = bridge_bit_list[1]
        assert bridge_type in tcpl_bridge_transport_dict
        if bridge_type not in seen_bridge_type_list:
            seen_bridge_type_list.append(bridge_type)
            client_transport_block += f"""ClientTransportPlugin {bridge_type} {
tcpl_bridge_transport_dict[bridge_type]}
"""
        bridge_block += f"{bridge_line}\n"
    torrc_contents += f"{client_transport_block}{bridge_block}"
    match tor_conf_info.proxy_type:
        case "HTTP / HTTPS":
            assert tor_conf_info.proxy_host is not None
            assert tor_conf_info.proxy_port is not None
            torrc_contents += f"""HTTPSProxy {tor_conf_info.proxy_host}:{
str(tor_conf_info.proxy_port)}
"""
            if (
                tor_conf_info.proxy_username is not None
                or tor_conf_info.proxy_password is not None
            ):
                torrc_contents += f"""HTTPSProxyAuthenticator {
tor_conf_info.proxy_username
if tor_conf_info.proxy_username is not None
else ""}:{tor_conf_info.proxy_password
if tor_conf_info.proxy_password is not None
else ""}
"""
        case "SOCKS4":
            assert tor_conf_info.proxy_host is not None
            assert tor_conf_info.proxy_port is not None
            torrc_contents += f"""Socks4Proxy {tor_conf_info.proxy_host}:{
str(tor_conf_info.proxy_port)}
"""
        case "SOCKS5":
            assert tor_conf_info.proxy_host is not None
            assert tor_conf_info.proxy_port is not None
            torrc_contents += f"""Socks5Proxy {tor_conf_info.proxy_host}:{
str(tor_conf_info.proxy_port)}
"""
            if (
                tor_conf_info.proxy_username is not None
                and tor_conf_info.proxy_password is not None
            ):
                torrc_contents += f"""Socks5ProxyUsername {
tor_conf_info.proxy_username}
Socks5ProxyPassword {
tor_conf_info.proxy_password}
"""

    write_exec_obj: subprocess.Popen[str] = tcpl_run_privileged_task_async(
        "tcp-write-torrc"
    )
    fifo_wait_count: int = 0
    ## Technically this should be a tri-state but this is easier.
    fifo_found: bool = False
    fifo_writable: bool = False
    while fifo_wait_count < 10:
        time.sleep(0.1)
        fifo_wait_count += 1
        if tcpl_torrc_comm_fifo.is_fifo():
            fifo_found = True
            if os.access(tcpl_torrc_comm_fifo, os.W_OK):
                fifo_writable = True
                break
    if not fifo_found:
        raise FileNotFoundError(
            f"No comm FIFO at '{str(tcpl_torrc_comm_fifo)}'!"
        )
    if not fifo_writable:
        raise PermissionError(
            f"Cannot write to comm FIFO at '{str(tcpl_torrc_comm_fifo)}'!"
        )
    tcpl_torrc_comm_fifo.write_text(torrc_contents, encoding="utf-8")

    stdout_data: str
    stderr_data: str
    stdout_data, stderr_data = write_exec_obj.communicate()
    if write_exec_obj.returncode != 0:
        raise RuntimeError(
            f"Torrc file write failed: {stdout_data + stderr_data}"
        )


def tcpl_adjust_etc_resolv_conf(bridge_line_list: list[str]) -> str | None:
    """
    Enables clearnet DNS resolution in Whonix if necessary for one of the
    chosen bridge types, otherwise disables it. Returns None if successful,
    an error message string otherwise.
    """

    if not whonix_gw_flag_file.is_file():
        return None

    do_enable_clearnet_dns: bool = False
    for bridge_line in bridge_line_list:
        bridge_bit_list: list[str] = bridge_line.split(" ", maxsplit=2)
        assert len(bridge_bit_list) > 1
        bridge_type: str = bridge_bit_list[1]
        if bridge_type in tcpl_clearnet_dns_bridge_type_list:
            do_enable_clearnet_dns = True
            break

    dns_adjust_info: subprocess.CompletedProcess[str]
    if do_enable_clearnet_dns:
        dns_adjust_info = tcpl_run_privileged_task_sync("anon-dns-add")
    else:
        dns_adjust_info = tcpl_run_privileged_task_sync("anon-dns-remove")

    if dns_adjust_info.returncode == 0:
        return None
    return dns_adjust_info.stdout + dns_adjust_info.stderr


## Tor's config file starts each bridge line with the configuration command
## 'Bridge', but the bridge lines supplied by BridgesDB do not start with
## 'Bridge'. Therefore we must convert between the two forms as needed.
def tcpl_bridge_lines_add_prefix(bridge_line_list: list[str]) -> list[str]:
    """
    Adds 'Bridge' prefixes to each line in bridge_line_list. Raises ValueError
    if a line already contains a prefix.
    """

    out_line_list: list[str] = []
    for bridge_line in bridge_line_list:
        if bridge_line.startswith("Bridge ") and bridge_line != "":
            raise ValueError(
                f"Bridge line '{bridge_line}' already starts with a 'Bridge' "
                + "prefix."
            )
        if bridge_line == "":
            continue
        out_line_list.append(f"Bridge {bridge_line}")
    return out_line_list


def tcpl_bridge_lines_remove_prefix(bridge_line_list: list[str]) -> list[str]:
    """
    Strips 'Bridge' prefixes from each line in bridge_line_list. Raises
    ValueError if a line does not contain a prefix.
    """

    out_line_list: list[str] = []
    for bridge_line in bridge_line_list:
        if not bridge_line.startswith("Bridge ") and bridge_line != "":
            raise ValueError(
                f"Bridge line '{bridge_line}' does not start with a 'Bridge' "
                + "prefix."
            )
        out_line_list.append(bridge_line.removeprefix("Bridge "))
    return out_line_list
