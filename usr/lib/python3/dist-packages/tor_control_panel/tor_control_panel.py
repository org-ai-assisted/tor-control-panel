#!/usr/bin/python3 -Bsu

## Copyright (c) 2018 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, global-statement, too-many-lines

"""
The configuration GUI for Tor on Whonix.
"""

import copy
import functools
import json
import os
import signal
import subprocess
import sys
from enum import Enum
from pathlib import Path
from types import FrameType
from typing import NoReturn, Any

from stem import Signal  # type: ignore
from stem.control import Controller  # type: ignore

from PyQt6.QtCore import (
    pyqtSignal,
    QObject,
    QRect,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
)
from PyQt6.QtGui import (
    QCursor,
    QDesktopServices,
    QIcon,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from sanitize_string.sanitize_string_lib import sanitize_string

from .tor_control_panel_lib import (
    TcplTorConfInfo,
    TcplTorStatus,
    TcplTorStatusField,
    tcpl_adjust_etc_resolv_conf,
    tcpl_blank_tor_conf_info,
    tcpl_bridges_default_path,
    tcpl_bridge_lines_add_prefix,
    tcpl_bridge_lines_remove_prefix,
    tcpl_bridge_type_custom_str,
    tcpl_bridge_type_list,
    tcpl_bridge_type_none_str,
    tcpl_default_port_for_protocol,
    tcpl_parse_torrc,
    tcpl_proxy_type_list,
    tcpl_proxy_type_none_str,
    tcpl_run_privileged_task_sync,
    tcpl_tor_auth_path,
    tcpl_tor_config_sane,
    tcpl_tor_control_path,
    tcpl_tor_log_path,
    tcpl_torrc_file,
    tcpl_tor_status_map,
    tcpl_write_torrc,
    whonix_gw_flag_file,
)

from .tor_status_watcher import TcplTorMonitor

tcp_window_title: str = "Tor Control Panel"

tcp_system_path: Path = Path(
    "/usr/lib/python3/dist-packages/tor_control_panel.py"
)

## These variables are not part of tor_control_panel_lib.py because their
## content differs slightly between Anon Connection Wizard and Tor Control
## Panel.
tcp_tor_censorship_help_text: str = """<p><b>Censorship Circumvention
Help</b></p>

<p>If you are unable to connect to the Tor network, your Internet provider or
another agency could be blocking Tor. Tor bridges can usually be used to work
around this, and are the recommended way to circumvent Tor censorship. Tor
Control Panel includes built-in bridges.</p>

<p>If the built-in Tor bridges do not work, and you cannot obtain others or
others also do not work, you can try using a third-party circumvention tool.
Set "Bridges type" to "None", then follow the below instructions for your
circumvention tool:</p>

<blockquote><b>VPN:</b><br>
1. Connect to the VPN server.<br>
2. In Tor Control Panel, click "Accept".</blockquote>

<blockquote><b>HTTP/Socks Proxy:</b><br>
1. Set "Proxy type" as appropriate.<br>
2. Input the desired proxy's details.<br>
3. Click "Accept".</blockquote>

<blockquote><b>Specialized Tool:</b><br>
1. Set up the tool to provide a proxy.<br>
2. Set "Proxy type" as appropriate.<br>
3. Input the tool's proxy details.<br>
4. Configure "Accept".</blockquote>
"""
tcp_proxy_help_text: str = """<p><b>Proxy Help</b></p>
<p>In some situations, you may want to route your traffic through a proxy
server before connecting to the Tor network. This is frequently useful when
using third-party circumvention tools.</p>

<p>Here is a brief explanation of proxy configuration options:</p>

<blockquote><b>Proxy Type:</b><br>
The protocol used by the proxy server. If you don't know the protocol, try each
one until one works.</blockquote>

<blockquote><b>Host:</b><br>
The domain name or IP address of the proxy server machine. If connecting to a
local proxy, use 127.0.0.1.</blockquote>

<blockquote><b>Port:</b><br>
The port the proxy software listens on. This will usually be advertised by the
proxy service or circumvention tool. It can be left blank to use a standard
port.</blockquote>

<blockquote><b>User, Pass:</b><br>
The username and password to authenticate to the proxy server. These are
usually not required.</blockquote>
"""
tcp_custom_bridges_help_text: str = """<p>As an alternative to using the
provided bridges, you can obtain a set of custom bridges using one of the
following methods:</p>

<p><b>1.</b> Use a web browser to visit:
<a>https://bridges.torproject.org/options</a></p>

<p><b>2.</b> Send an email to <b>bridges@torproject.org</b> with the line 'get
bridges' in the body of the message. You must send this request from one of
the following email providers (listed in order of preference):<br>
<a>https://www.riseup.net</a>, <a>https://mail.google.com</a></p>

<p>For assistance, visit
<a>https://torproject.org/about/contact.html#support</a></p>

<p>Paste the bridge list received from the Tor Project below:</p>"""


class SyncConfigUiResult(Enum):
    """
    Result code from sync_config_ui_to_tor_conf_info.
    """

    SUCCESS = 1
    BAD_BRIDGE_LINE = 2
    PROXY_MISSING_HOST = 3
    PROXY_PORT_NOT_INTEGER = 4
    PROXY_PORT_OUT_OF_RANGE = 5
    PROXY_DOES_NOT_SUPPORT_AUTH = 6
    PROXY_SOCKS5_USER_WITHOUT_PASS = 7
    PROXY_SOCKS5_PASS_WITHOUT_USER = 8
    PROXY_SOCKS5_USER_LEN_BAD = 9
    PROXY_SOCKS5_PASS_LEN_BAD = 10


# pylint: disable=too-many-instance-attributes, too-many-public-methods
class TorControlPanelDialog(QDialog):
    """
    Application window.
    """

    # pylint: disable=too-many-statements
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        ## BEGIN Window configuration {
        self.setWindowTitle(tcp_window_title)
        self.setMinimumSize(700, 565)
        self.resize(700, 565)
        ## END Window configuration }

        ## BEGIN App constants {
        self.base_tcp_path: Path
        if Path(__file__).resolve() == tcp_system_path:
            self.base_tcp_path = Path("/usr/share/tor-control-panel")
        else:
            self.base_tcp_path = Path(
                Path(__file__).parent.parent.parent.parent.parent,
                "share/tor-control-panel",
            )
        self.base_icon_path: Path = Path(self.base_tcp_path, "icons")
        self.refresh_icon_path: Path = Path(self.base_icon_path, "refresh.png")
        self.exit_icon_path: Path = Path(self.base_icon_path, "exit.png")
        self.restart_icon_path: Path = Path(self.base_icon_path, "restart.png")
        self.stop_icon_path: Path = Path(self.base_icon_path, "stop.png")
        self.tools_icon_path: Path = Path(self.base_icon_path, "tools.png")
        self.help_icon_path: Path = Path(self.base_icon_path, "help.png")
        self.prev_icon_path: Path = Path(self.base_icon_path, "prev.png")
        self.accept_icon_path: Path = Path(self.base_icon_path, "accept.png")
        self.onion_icon_path: Path = Path(self.base_icon_path, "onion.png")
        self.newnym_icon_path: Path = Path(self.base_icon_path, "newnym.png")
        ## END App constants }

        ## BEGIN App UI {
        self.core_layout: QVBoxLayout = QVBoxLayout()

        self.tab_widget: QTabWidget = QTabWidget()
        self.core_layout.addWidget(self.tab_widget)

        ## BEGIN Control tab {
        self.control_tab: QStackedWidget = QStackedWidget()

        ## BEGIN Control main page {
        self.control_tab_main_page: QWidget = QWidget()
        self.control_tab_main_layout: QVBoxLayout = QVBoxLayout()

        ## BEGIN Status section {
        self.status_widget: QWidget = QWidget()
        self.status_layout: QHBoxLayout = QHBoxLayout()
        self.status_layout.setContentsMargins(10, 10, 10, 10)

        ## This is a bit of a hack; we want a small colored rectangle with some
        ## words on it. A disabled QPushButton with a stylesheet does that.
        self.status_indicator: QPushButton = QPushButton("Tor status")
        self.status_indicator.setEnabled(False)
        self.status_layout.addWidget(
            self.status_indicator, 0, Qt.AlignmentFlag.AlignTop
        )

        self.status_stack_layout: QVBoxLayout = QVBoxLayout()
        ## We can't add right padding to the status indicator directly, so
        ## instead we add left padding to the layout that holds everything to
        ## the right of the indicator.
        self.status_stack_layout.setContentsMargins(10, 0, 0, 0)

        self.status_label: QLabel = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.status_stack_layout.addWidget(self.status_label)

        self.status_stack_spacer: QSpacerItem = QSpacerItem(0, 20)
        self.status_stack_layout.addItem(self.status_stack_spacer)

        self.bootstrap_label: QLabel = QLabel()
        self.bootstrap_label.setWordWrap(True)
        self.bootstrap_label.setTextFormat(Qt.TextFormat.PlainText)
        self.bootstrap_label.setVisible(False)
        self.status_stack_layout.addWidget(self.bootstrap_label)

        self.bootstrap_progress: QProgressBar = QProgressBar()
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)
        self.bootstrap_progress.setVisible(False)
        self.status_stack_layout.addWidget(self.bootstrap_progress)

        self.status_stack_layout.addStretch()
        self.status_layout.addLayout(self.status_stack_layout)
        self.status_widget.setLayout(self.status_layout)
        self.status_widget.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding
        )
        self.control_tab_main_layout.addWidget(self.status_widget)
        ## END Status section }

        self.control_tab_main_layout.addStretch()

        self.config_control_frame: QFrame = QFrame()
        self.config_control_frame.setLineWidth(2)
        self.config_control_frame.setFrameStyle(
            QFrame.Shape.Panel | QFrame.Shadow.Sunken
        )

        self.config_control_layout: QHBoxLayout = QHBoxLayout()

        ## BEGIN User configuration group {
        self.user_config_group: QGroupBox = QGroupBox("User configuration")
        self.user_config_layout: QGridLayout = QGridLayout()

        self.bridges_type_static_label: QLabel = QLabel("Bridges type:")
        self.user_config_layout.addWidget(self.bridges_type_static_label, 0, 0)

        self.bridges_type_label: QLabel = QLabel("Unknown")
        self.bridges_type_label.setStyleSheet("font: bold;")
        self.bridges_type_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.user_config_layout.addWidget(self.bridges_type_label, 0, 1)

        self.bridges_type_combo_box: QComboBox = QComboBox()
        self.bridges_type_combo_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.bridges_type_combo_box.addItem(tcpl_bridge_type_list[0])
        self.bridges_type_combo_box.insertSeparator(1)
        for bridge_type_str in tcpl_bridge_type_list[1:-1]:
            self.bridges_type_combo_box.addItem(bridge_type_str)
        self.bridges_type_combo_box.insertSeparator(
            self.bridges_type_combo_box.count()
        )
        self.bridges_type_combo_box.addItem(tcpl_bridge_type_list[-1])
        self.bridges_type_combo_box.setVisible(False)
        self.user_config_layout.addWidget(self.bridges_type_combo_box, 0, 2)

        self.bridges_help_button: QPushButton = QPushButton(
            QIcon(str(self.help_icon_path)), ""
        )
        self.bridges_help_button.setMaximumWidth(20)
        self.bridges_help_button.clicked.connect(self.show_censorship_help)
        self.bridges_help_button.setFlat(True)
        self.bridges_help_button.setVisible(False)
        self.user_config_layout.addWidget(self.bridges_help_button, 0, 3)

        self.proxy_type_static_label: QLabel = QLabel("Proxy type:")
        self.user_config_layout.addWidget(self.proxy_type_static_label, 1, 0)

        self.proxy_type_label: QLabel = QLabel("Unknown")
        self.proxy_type_label.setStyleSheet("font: bold;")
        self.proxy_type_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.user_config_layout.addWidget(self.proxy_type_label, 1, 1)

        self.proxy_type_combo_box: QComboBox = QComboBox()
        self.proxy_type_combo_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.proxy_type_combo_box.addItem(tcpl_proxy_type_list[0])
        self.proxy_type_combo_box.insertSeparator(1)
        for proxy_type_str in tcpl_proxy_type_list[1:]:
            self.proxy_type_combo_box.addItem(proxy_type_str)
        self.proxy_type_combo_box.activated.connect(
            self.show_proxy_config_maybe
        )
        self.proxy_type_combo_box.setVisible(False)
        self.user_config_layout.addWidget(self.proxy_type_combo_box, 1, 2)

        self.proxy_help_button: QPushButton = QPushButton(
            QIcon(str(self.help_icon_path)), ""
        )
        self.proxy_help_button.setMaximumWidth(20)
        self.proxy_help_button.clicked.connect(self.show_proxy_help)
        self.proxy_help_button.setFlat(True)
        self.proxy_help_button.setVisible(False)
        self.user_config_layout.addWidget(self.proxy_help_button, 1, 3)

        ## BEGIN Proxy configuration layout {
        self.proxy_config_widget: QWidget = QWidget()
        self.proxy_config_layout: QGridLayout = QGridLayout()
        self.proxy_host_label: QLabel = QLabel("Host:")
        self.proxy_config_layout.addWidget(
            self.proxy_host_label, 0, 0, Qt.AlignmentFlag.AlignRight
        )

        self.proxy_host_line_edit: QLineEdit = QLineEdit()
        self.proxy_host_line_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.proxy_host_line_edit.setPlaceholderText("Address/domain")
        self.proxy_config_layout.addWidget(self.proxy_host_line_edit, 0, 1)

        self.proxy_port_label: QLabel = QLabel("Port:")
        self.proxy_config_layout.addWidget(
            self.proxy_port_label, 0, 2, Qt.AlignmentFlag.AlignRight
        )

        self.proxy_port_line_edit: QLineEdit = QLineEdit()
        self.proxy_port_line_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.proxy_port_line_edit.setPlaceholderText("1-65535")
        self.proxy_config_layout.addWidget(self.proxy_port_line_edit, 0, 3)

        self.proxy_user_label: QLabel = QLabel("User:")
        self.proxy_config_layout.addWidget(
            self.proxy_user_label, 1, 0, Qt.AlignmentFlag.AlignRight
        )

        self.proxy_user_line_edit: QLineEdit = QLineEdit()
        self.proxy_user_line_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.proxy_user_line_edit.setPlaceholderText("Optional")
        self.proxy_config_layout.addWidget(self.proxy_user_line_edit, 1, 1)

        self.proxy_pass_label: QLabel = QLabel("Pass:")
        self.proxy_config_layout.addWidget(
            self.proxy_pass_label, 1, 2, Qt.AlignmentFlag.AlignRight
        )

        self.proxy_pass_line_edit: QLineEdit = QLineEdit()
        self.proxy_pass_line_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.proxy_pass_line_edit.setPlaceholderText("Optional")
        self.proxy_config_layout.addWidget(self.proxy_pass_line_edit, 1, 3)
        self.proxy_config_widget.setLayout(self.proxy_config_layout)
        self.user_config_layout.addWidget(self.proxy_config_widget, 2, 0, 1, 3)
        self.proxy_config_widget.setVisible(False)
        ## END Proxy configuration layout }

        self.user_config_layout.setRowStretch(3, 1)

        self.enable_network_checkbox: QCheckBox = QCheckBox("Enable network?")
        self.enable_network_checkbox.setEnabled(False)
        self.user_config_layout.addWidget(self.enable_network_checkbox, 4, 0)

        self.cancel_config_button: QPushButton = QPushButton(
            QIcon(str(self.prev_icon_path)), ""
        )
        self.cancel_config_button.setMaximumWidth(20)
        self.cancel_config_button.clicked.connect(self.cancel_configure_tor)
        self.cancel_config_button.setFlat(True)
        self.cancel_config_button.setVisible(False)
        self.user_config_layout.addWidget(self.cancel_config_button, 4, 3)

        self.user_config_group.setLayout(self.user_config_layout)
        self.user_config_group.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.config_control_layout.addWidget(self.user_config_group)
        ## END User configuration group }

        ## BEGIN Control group {
        self.control_group: QGroupBox = QGroupBox("Control")
        self.control_group_layout: QVBoxLayout = QVBoxLayout()

        self.restart_tor_button: QPushButton = QPushButton(
            QIcon(str(self.restart_icon_path)), " Restart Tor"
        )
        self.restart_tor_button.clicked.connect(self.restart_tor)
        self.restart_tor_button.setIconSize(QSize(28, 28))
        self.restart_tor_button.setFlat(True)
        self.restart_tor_button.setStyleSheet("text-align: left;")
        self.control_group_layout.addWidget(self.restart_tor_button)

        self.stop_tor_button: QPushButton = QPushButton(
            QIcon(str(self.stop_icon_path)), " Stop Tor"
        )
        self.stop_tor_button.clicked.connect(self.stop_tor)
        self.stop_tor_button.setIconSize(QSize(28, 28))
        self.stop_tor_button.setFlat(True)
        self.stop_tor_button.setStyleSheet("text-align: left;")
        self.control_group_layout.addWidget(self.stop_tor_button)

        self.configure_button: QPushButton = QPushButton(
            QIcon(str(self.tools_icon_path)), " Configure"
        )
        self.configure_button.clicked.connect(self.configure_tor)
        self.configure_button.setIconSize(QSize(28, 28))
        self.configure_button.setFlat(True)
        self.configure_button.setStyleSheet("text-align: left;")
        self.control_group_layout.addWidget(self.configure_button)

        self.accept_button: QPushButton = QPushButton(
            QIcon(str(self.accept_icon_path)), " Accept"
        )
        self.accept_button.clicked.connect(
            functools.partial(self.accept_tor_config, False)
        )
        self.accept_button.setIconSize(QSize(28, 28))
        self.accept_button.setFlat(True)
        self.accept_button.setStyleSheet("text-align: left;")
        self.accept_button.setVisible(False)
        self.control_group_layout.addWidget(self.accept_button)

        self.control_group_layout.addStretch()

        self.control_group.setLayout(self.control_group_layout)
        self.config_control_layout.addWidget(self.control_group)
        ## END Control group }

        self.config_control_frame.setLayout(self.config_control_layout)
        self.config_control_frame.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
        )
        self.control_tab_main_layout.addWidget(self.config_control_frame)
        self.control_tab_main_page.setLayout(self.control_tab_main_layout)
        self.control_tab.addWidget(self.control_tab_main_page)
        ## END Control main page }

        ## BEGIN Control custom bridges page {
        self.control_tab_custom_bridges_page: QWidget = QWidget()
        self.control_tab_custom_bridges_layout: QVBoxLayout = QVBoxLayout()

        self.custom_bridges_help_label: QLabel = QLabel(
            tcp_custom_bridges_help_text
        )
        self.custom_bridges_help_label.linkActivated.connect(
            functools.partial(open_link_maybe, parent=self)
        )
        self.custom_bridges_help_label.setWordWrap(True)
        self.control_tab_custom_bridges_layout.addWidget(
            self.custom_bridges_help_label
        )

        self.custom_bridges_text_edit: QTextEdit = QTextEdit()
        self.custom_bridges_text_edit.setAcceptRichText(False)
        self.custom_bridges_text_edit.setFontFamily("Monospace")
        self.control_tab_custom_bridges_layout.addWidget(
            self.custom_bridges_text_edit
        )

        self.custom_bridges_button_layout: QHBoxLayout = QHBoxLayout()
        self.custom_bridges_button_layout.addStretch()

        self.custom_bridges_cancel_button: QPushButton = QPushButton(
            QIcon(str(self.prev_icon_path)), " Cancel"
        )
        self.custom_bridges_cancel_button.clicked.connect(
            self.custom_bridges_cancel
        )
        self.custom_bridges_button_layout.addWidget(
            self.custom_bridges_cancel_button
        )

        self.custom_bridges_accept_button: QPushButton = QPushButton(
            QIcon(str(self.accept_icon_path)), " Accept"
        )
        self.custom_bridges_accept_button.clicked.connect(
            functools.partial(self.accept_tor_config, True)
        )
        self.custom_bridges_button_layout.addWidget(
            self.custom_bridges_accept_button
        )
        self.control_tab_custom_bridges_layout.addLayout(
            self.custom_bridges_button_layout
        )

        self.control_tab_custom_bridges_page.setLayout(
            self.control_tab_custom_bridges_layout
        )
        self.control_tab.addWidget(self.control_tab_custom_bridges_page)
        ## END Control custom bridges page }

        self.tab_widget.addTab(self.control_tab, "Control")
        ## END Control tab }

        ## BEGIN Utilities tab {
        self.utilities_tab: QWidget = QWidget()
        self.utilities_tab_layout: QVBoxLayout = QVBoxLayout()

        self.onion_circuits_frame: QFrame = QFrame()
        self.onion_circuits_frame.setLineWidth(2)
        self.onion_circuits_frame.setFrameStyle(
            QFrame.Shape.Panel | QFrame.Shadow.Sunken
        )

        self.onion_circuits_frame_layout: QVBoxLayout = QVBoxLayout()
        self.onion_circuits_button_layout: QHBoxLayout = QHBoxLayout()
        self.onion_circuits_button: QPushButton = QPushButton(
            QIcon(str(self.onion_icon_path)), " Onion Circuits"
        )
        self.onion_circuits_button.clicked.connect(self.show_onion_circuits)
        self.onion_circuits_button_layout.addWidget(self.onion_circuits_button)
        self.onion_circuits_button_layout.addStretch()
        self.onion_circuits_frame_layout.addLayout(
            self.onion_circuits_button_layout
        )

        self.onion_circuits_label: QLabel = QLabel(
            """Displays Tor circuits and streams. It allows inspection of the \
circuits built by the locally running Tor daemon."""
        )
        self.onion_circuits_label.setWordWrap(True)
        self.onion_circuits_frame_layout.addWidget(self.onion_circuits_label)
        self.onion_circuits_frame.setLayout(self.onion_circuits_frame_layout)
        self.utilities_tab_layout.addWidget(self.onion_circuits_frame)

        self.newnym_frame: QFrame = QFrame()
        self.newnym_frame.setLineWidth(2)
        self.newnym_frame.setFrameStyle(
            QFrame.Shape.Panel | QFrame.Shadow.Sunken
        )

        self.newnym_frame_layout: QVBoxLayout = QVBoxLayout()
        self.newnym_button_layout: QHBoxLayout = QHBoxLayout()
        self.newnym_button: QPushButton = QPushButton(
            QIcon(str(self.newnym_icon_path)), " Request new Tor circuit"
        )
        self.newnym_button.clicked.connect(self.send_newnym)
        self.newnym_button_layout.addWidget(self.newnym_button)
        self.newnym_button_layout.addStretch()
        self.newnym_frame_layout.addLayout(self.newnym_button_layout)

        self.newnym_label: QLabel = QLabel(
            """<p>Use a fresh Tor route for <b>new</b> connections. This asks \
Tor to build new circuits, so future connections might take a different path \
(and might use a different Tor exit relay).</p>

<p>Technically, this sends signal NEWNYM to Tor. For more information, see \
<a href="https://www.whonix.org/wiki/Stream_Isolation">Stream \
Isolation</a>.</p>"""
        )
        self.newnym_label.setWordWrap(True)
        self.newnym_label.linkActivated.connect(
            functools.partial(open_link_maybe, parent=self)
        )
        self.newnym_frame_layout.addWidget(self.newnym_label)
        self.newnym_frame.setLayout(self.newnym_frame_layout)
        self.utilities_tab_layout.addWidget(self.newnym_frame)
        self.utilities_tab_layout.addStretch()

        self.utilities_tab.setLayout(self.utilities_tab_layout)
        self.tab_widget.addTab(self.utilities_tab, "Utilities")
        ## END Utilities tab }

        ## BEGIN Logs tab {
        self.logs_tab: QWidget = QWidget()
        self.logs_tab_layout: QVBoxLayout = QVBoxLayout()

        self.logs_control_layout: QHBoxLayout = QHBoxLayout()
        self.logs_radiobutton_frame: QFrame = QFrame()
        self.logs_radiobutton_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        self.logs_radiobutton_layout: QGridLayout = QGridLayout()
        self.logs_files_label: QLabel = QLabel("Files")
        self.logs_logs_label: QLabel = QLabel("Logs")
        self.logs_radiobutton_layout.addWidget(
            self.logs_files_label, 0, 0, 1, 1
        )
        self.logs_radiobutton_layout.addWidget(self.logs_logs_label, 0, 1, 1, 1)

        self.logs_torrc_radio_button: QRadioButton = QRadioButton("torrc")
        self.logs_torrc_radio_button.clicked.connect(self.load_logs)
        self.logs_tor_log_radio_button: QRadioButton = QRadioButton("Tor log")
        self.logs_tor_log_radio_button.clicked.connect(self.load_logs)
        self.logs_systemd_journal_radio_button: QRadioButton = QRadioButton(
            "systemd journal"
        )
        self.logs_systemd_journal_radio_button.clicked.connect(self.load_logs)
        self.logs_radiobutton_layout.addWidget(
            self.logs_torrc_radio_button, 1, 0, 1, 1
        )
        self.logs_radiobutton_layout.addWidget(
            self.logs_tor_log_radio_button, 1, 1, 1, 1
        )
        self.logs_radiobutton_layout.addWidget(
            self.logs_systemd_journal_radio_button, 2, 1, 1, 1
        )
        self.logs_tor_log_radio_button.setChecked(True)
        self.logs_radiobutton_frame.setLayout(self.logs_radiobutton_layout)

        self.logs_control_layout.addWidget(self.logs_radiobutton_frame)

        self.logs_refresh_widget: QWidget = QWidget()
        self.logs_refresh_widget.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )
        self.logs_refresh_layout: QVBoxLayout = QVBoxLayout()
        self.logs_refresh_layout.addStretch()

        self.logs_refresh_info_label: QLabel = QLabel(
            """<i>Note: Logs are automatically refreshed when the \"Logs\" tab
is clicked or when a new log or file is selected.</i>"""
        )
        self.logs_refresh_info_label.setWordWrap(True)
        self.logs_refresh_layout.addWidget(self.logs_refresh_info_label)

        self.logs_refresh_button_layout: QHBoxLayout = QHBoxLayout()
        self.logs_refresh_button_layout.addStretch()
        self.logs_refresh_button: QPushButton = QPushButton(
            QIcon(str(self.refresh_icon_path)), " Refresh"
        )
        self.logs_refresh_button.clicked.connect(self.load_logs)
        self.logs_refresh_button_layout.addWidget(self.logs_refresh_button)
        self.logs_refresh_layout.addLayout(self.logs_refresh_button_layout)
        self.logs_refresh_widget.setLayout(self.logs_refresh_layout)
        self.logs_control_layout.addWidget(self.logs_refresh_widget)
        self.logs_tab_layout.addLayout(self.logs_control_layout)

        self.logs_text_edit: QTextEdit = QTextEdit()
        self.logs_text_edit.setAcceptRichText(False)
        self.logs_text_edit.setReadOnly(True)
        self.logs_text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.logs_text_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.logs_tab_layout.addWidget(self.logs_text_edit)

        self.logs_tab.setLayout(self.logs_tab_layout)
        self.tab_widget.addTab(self.logs_tab, "Logs")
        ## END Logs tab }

        self.tab_widget.currentChanged.connect(self.handle_tab_switch)

        self.button_bar_layout: QHBoxLayout = QHBoxLayout()
        self.bridges_wiki_help_button: QPushButton = QPushButton(
            QIcon(str(self.help_icon_path)), " Bridges Help (wiki)"
        )
        self.bridges_wiki_help_button.clicked.connect(
            functools.partial(
                open_link_maybe, "https://whonix.org/wiki/Bridges", parent=self
            )
        )
        self.button_bar_layout.addWidget(self.bridges_wiki_help_button)

        self.tcp_wiki_help_button: QPushButton = QPushButton(
            QIcon(str(self.help_icon_path)), " Tor Control Panel Help (wiki)"
        )
        self.tcp_wiki_help_button.clicked.connect(
            functools.partial(
                open_link_maybe,
                "https://whonix.org/wiki/Tor-control-panel",
                parent=self,
            )
        )
        self.button_bar_layout.addWidget(self.tcp_wiki_help_button)
        self.button_bar_layout.addStretch()

        self.exit_button: QPushButton = QPushButton(
            QIcon(str(self.exit_icon_path)),
            " Exit",
        )
        self.exit_button.clicked.connect(self.accept)
        self.button_bar_layout.addWidget(self.exit_button)
        self.core_layout.addLayout(self.button_bar_layout)

        self.setLayout(self.core_layout)
        ## END App UI }

        ## BEGIN Business logic setup {
        self.tor_conf_info: TcplTorConfInfo = self.parse_torrc()

        ## Debugging.
        print(self.tor_conf_info)

        self.sync_config_info()

        self.button_lock_dict: dict[QPushButton, set[str]] = {
            self.restart_tor_button: set(),
            self.stop_tor_button: set(),
            self.configure_button: set(),
        }
        self.tor_status: TcplTorStatus = TcplTorStatus.UNKNOWN
        self.sync_status_info()

        self.tor_monitor: TcplTorMonitor = TcplTorMonitor()
        self.tor_monitor.torActiveChanged.connect(self.tor_active_changed)
        self.tor_monitor.torBootstrapChanged.connect(self.tor_bootstrap_changed)
        self.tor_monitor.torControllerConnectFailed.connect(
            self.tor_controller_connect_failed
        )
        self.tor_monitor.start_watch()
        ## END Business logic setup }

    def parse_torrc(self) -> TcplTorConfInfo:
        """
        Parses the Tor Control Panel torrc file and (re-)initializes
        self.tor_conf_info. Pops up a warning disalog if the file cannot be
        parsed.
        """

        tmp_tor_conf_info: TcplTorConfInfo | str = tcpl_parse_torrc()
        if isinstance(tmp_tor_conf_info, TcplTorConfInfo):
            return tmp_tor_conf_info

        QMessageBox.warning(
            None,
            tcp_window_title,
            f"""<p>WARNING: Tor configuration could not be loaded! Details:</p>
<blockquote><pre>{tmp_tor_conf_info}</pre></blockquote>""",
        )
        return copy.deepcopy(tcpl_blank_tor_conf_info)

    def handle_tab_switch(self, index: int) -> None:
        """
        Performs any actions that need to be done when the user switches tabs.
        """

        if index == self.tab_widget.indexOf(self.logs_tab):
            ## Automatically (re)load logs any time the user switches to the
            ## 'Logs' tab.
            self.load_logs()

    def sync_config_info(self) -> None:
        """
        Updates Tor config widgets to match self.tor_conf_info.
        """

        self.enable_network_checkbox.setCheckState(
            Qt.CheckState.Checked
            if self.tor_conf_info.network_enabled
            or self.tor_conf_info.network_enabled is None
            else Qt.CheckState.Unchecked
        )

        if not self.tor_conf_info.bridges_enabled:
            self.bridges_type_label.setText(tcpl_bridge_type_none_str)
            self.bridges_type_combo_box.setCurrentText(
                tcpl_bridge_type_none_str
            )
        else:
            if len(self.tor_conf_info.bridge_type_set) == 1:
                bridge_type: str = list(self.tor_conf_info.bridge_type_set)[0]
                self.bridges_type_label.setText(bridge_type)
                self.bridges_type_combo_box.setCurrentText(bridge_type)
            else:
                self.bridges_type_label.setText(tcpl_bridge_type_custom_str)
                self.bridges_type_combo_box.setCurrentText(
                    tcpl_bridge_type_custom_str
                )
            self.custom_bridges_text_edit.setPlainText(
                "\n".join(
                    tcpl_bridge_lines_remove_prefix(
                        self.tor_conf_info.bridge_line_list
                    )
                )
            )

        if self.tor_conf_info.proxy_type is None:
            self.proxy_type_label.setText(tcpl_proxy_type_none_str)
            self.proxy_type_combo_box.setCurrentText(tcpl_proxy_type_none_str)
        else:
            assert self.tor_conf_info.proxy_host is not None
            assert self.tor_conf_info.proxy_port is not None
            self.proxy_type_label.setText(self.tor_conf_info.proxy_type)
            self.proxy_type_combo_box.setCurrentText(
                self.tor_conf_info.proxy_type
            )
            self.proxy_host_line_edit.setText(self.tor_conf_info.proxy_host)
            self.proxy_port_line_edit.setText(
                str(self.tor_conf_info.proxy_port)
            )
            self.proxy_user_line_edit.setText(
                self.tor_conf_info.proxy_username
                if self.tor_conf_info.proxy_username is not None
                else ""
            )
            self.proxy_pass_line_edit.setText(
                self.tor_conf_info.proxy_password
                if self.tor_conf_info.proxy_password is not None
                else ""
            )

    def sync_button_lock(self) -> None:
        """
        Enables or disables buttons in the control button stack according to
        the button lock dict.
        """

        for button, lock_set in self.button_lock_dict.items():
            button.setEnabled(len(lock_set) == 0)

    def sync_status_info(self) -> None:
        """
        Updates Tor status widgets to match self.tor_status.
        """

        assert self.tor_status in tcpl_tor_status_map
        tor_status_map: dict[TcplTorStatusField, str] = tcpl_tor_status_map[
            self.tor_status
        ]
        assert TcplTorStatusField.COLOR in tor_status_map
        assert TcplTorStatusField.STATUS_TEXT in tor_status_map
        self.status_indicator.setStyleSheet(
            "background-color: "
            + f'"{tor_status_map[TcplTorStatusField.COLOR]}"; '
            + "color: white; "
            + "font: bold;"
        )
        self.status_label.setText(
            tor_status_map[TcplTorStatusField.STATUS_TEXT]
        )

        ## Note that self.accept_button is NEVER disabled. This way if the user
        ## is editing Tor configuration when Tor changes state, they can get
        ## out of the configuration UI no matter what.
        ##
        ## REMINDER: If we ever add a feature other than configure mode that
        ## also locks the control buttons, we will probably want to use a
        ## single shared variable to lock the control buttons.
        match self.tor_status:
            case TcplTorStatus.UNKNOWN:
                self.button_lock_dict[self.restart_tor_button].add(
                    "sync_status_info"
                )
                self.button_lock_dict[self.stop_tor_button].add(
                    "sync_status_info"
                )
                self.button_lock_dict[self.configure_button].add(
                    "sync_status_info"
                )
                self.bootstrap_label.setVisible(False)
                self.bootstrap_progress.setVisible(False)
            case (
                TcplTorStatus.RUNNING
                | TcplTorStatus.DISABLED_RUNNING
                | TcplTorStatus.NO_CONTROLLER
            ):
                self.button_lock_dict[self.restart_tor_button].discard(
                    "sync_status_info"
                )
                self.button_lock_dict[self.stop_tor_button].discard(
                    "sync_status_info"
                )
                self.button_lock_dict[self.configure_button].discard(
                    "sync_status_info"
                )
                self.bootstrap_label.setVisible(False)
                self.bootstrap_progress.setVisible(False)
            case TcplTorStatus.STOPPED | TcplTorStatus.DISABLED:
                self.button_lock_dict[self.restart_tor_button].discard(
                    "sync_status_info"
                )
                self.button_lock_dict[self.stop_tor_button].add(
                    "sync_status_info"
                )
                self.button_lock_dict[self.configure_button].discard(
                    "sync_status_info"
                )
                self.bootstrap_label.setVisible(False)
                self.bootstrap_progress.setVisible(False)
            case TcplTorStatus.ACQUIRING:
                self.button_lock_dict[self.restart_tor_button].add(
                    "sync_status_info"
                )
                ## Allows the user to abort a stuck bootstrap
                self.button_lock_dict[self.stop_tor_button].discard(
                    "sync_status_info"
                )
                self.button_lock_dict[self.configure_button].discard(
                    "sync_status_info"
                )
                self.bootstrap_label.setVisible(True)
                self.bootstrap_progress.setVisible(True)

        self.sync_button_lock()

    def tor_active_changed(self, is_running: bool) -> None:
        """
        Updates the Tor status when Tor's running-or-stopped state is detected
        or changes.
        """

        ## Debugging.
        print(f"tor_active_changed: is_running: {is_running}")

        ## Reset the bootstrap progress indicators.
        self.bootstrap_progress.setValue(0)
        self.bootstrap_label.setText("Bootstrapping...")

        ## TcplTorMonitor will always send a torActiveChanged signal before
        ## sending any torBootstrapChanged signals. It is therefore safe to
        ## assume that Tor is in an "acquiring" or "disabled-running" state if
        ## torActiveChanged(true) is received.

        if not is_running:
            self.tor_status = (
                TcplTorStatus.STOPPED
                if self.tor_conf_info.network_enabled
                or self.tor_conf_info.network_enabled is None
                else TcplTorStatus.DISABLED
            )
        else:
            self.tor_status = (
                TcplTorStatus.ACQUIRING
                if self.tor_conf_info.network_enabled
                or self.tor_conf_info.network_enabled is None
                else TcplTorStatus.DISABLED_RUNNING
            )
        self.sync_status_info()

    def tor_bootstrap_changed(
        self, progress_int: int, tag_str: str, summary_str: str
    ) -> None:
        """
        Updates the Tor status when Tor's bootstrap state is detected or
        changes.
        """

        ## Debugging.
        print(
            f"tor_bootstrap_changed: Progress: {progress_int}; "
            + f"Tag: '{tag_str}'; Summary: '{summary_str}'"
        )

        self.bootstrap_progress.setValue(progress_int)
        self.bootstrap_label.setText(summary_str)
        if self.tor_status != TcplTorStatus.DISABLED_RUNNING:
            if tag_str == "done":
                self.tor_status = TcplTorStatus.RUNNING
            elif self.tor_status != TcplTorStatus.ACQUIRING:
                self.tor_status = TcplTorStatus.ACQUIRING
        self.sync_status_info()

    def tor_controller_connect_failed(self) -> None:
        """
        Updates the Tor status when the Tor monitor is unable to connect to
        Tor's control port.
        """

        self.tor_status = TcplTorStatus.NO_CONTROLLER
        self.sync_status_info()

    def show_censorship_help(self) -> None:
        """
        Pops up a modal dialog with information about Tor bridges.
        """

        QMessageBox.information(
            self,
            tcp_window_title,
            tcp_tor_censorship_help_text,
        )

    def show_proxy_help(self) -> None:
        """
        Pops up a modal dialog with information about using proxies with Tor.
        """

        QMessageBox.information(
            self,
            tcp_window_title,
            tcp_proxy_help_text,
        )

    def restart_tor(self) -> None:
        """
        Restarts the Tor process.
        """

        tor_restart_info: subprocess.CompletedProcess[str] = (
            tcpl_run_privileged_task_sync("tcp-tor-control-restart")
        )
        if tor_restart_info.returncode != 0:
            tor_restart_log: str = (
                tor_restart_info.stdout + tor_restart_info.stderr
            )
            QMessageBox.warning(
                self,
                tcp_window_title,
                f"""<p>ERROR: Could not restart Tor! Details:</p>
<blockquote><pre>{sanitize_string(tor_restart_log)}</pre></blockquote>""",
            )
        else:
            ## TcplTorMonitor cannot reliably detect when Tor restarts, most
            ## likely because the filesystem events that occur when this
            ## happens are too rapid-fire for QFileSystemWatcher to notice the
            ## Tor control socket disappearing and reappearing. Therefore we
            ## have to trigger tor_active_changed ourselves.
            self.tor_active_changed(True)

    def stop_tor(self) -> None:
        """
        Stops the Tor process.
        """

        tor_stop_info: subprocess.CompletedProcess[str] = (
            tcpl_run_privileged_task_sync("tcp-tor-control-stop")
        )
        if tor_stop_info.returncode != 0:
            tor_stop_log: str = tor_stop_info.stdout + tor_stop_info.stderr
            QMessageBox.warning(
                self,
                tcp_window_title,
                f"""<p>ERROR: Could not stop Tor! Details:</p>
<blockquote><pre>{sanitize_string(tor_stop_log)}</pre></blockquote>""",
            )

    def configure_tor(self) -> None:
        """
        Enables the user configuration UI.
        """

        self.config_ui_toggle(enable_ui=True)

    # pylint: disable=unused-argument
    def show_proxy_config_maybe(self, proxy_type: str) -> None:
        """
        Runs show_or_hide_proxy_config when the user changes the proxy setting.
        """

        self.show_or_hide_proxy_config(allow_show=True)

    def show_or_hide_proxy_config(self, allow_show: bool) -> None:
        """
        Shows the proxy configuration widgets if applicable, hide otherwise.
        """

        self.proxy_config_widget.setVisible(
            allow_show
            and self.proxy_type_combo_box.currentText()
            != tcpl_proxy_type_none_str
        )

    def accept_tor_config(self, from_custom_bridges_page: bool = False) -> None:
        """
        Accepts the users changes to Tor configuration.
        """

        should_restart_tor: bool = False

        if (
            self.bridges_type_combo_box.currentText()
            == tcpl_bridge_type_custom_str
            and not from_custom_bridges_page
        ):
            self.control_tab.setCurrentWidget(
                self.control_tab_custom_bridges_page
            )
            return
        self.control_tab.setCurrentWidget(self.control_tab_main_page)

        wait_cursor: QCursor = QCursor(Qt.CursorShape.WaitCursor)
        QApplication.setOverrideCursor(wait_cursor)

        sync_config_ui_result: SyncConfigUiResult
        bridge_line_list: list[str]
        if from_custom_bridges_page:
            bridge_line_list = tcpl_bridge_lines_add_prefix(
                self.custom_bridges_text_edit.toPlainText().split("\n")
            )
            sync_config_ui_result = self.sync_config_ui_to_tor_conf_info(
                bridge_line_list
            )
        else:
            sync_config_ui_result = self.sync_config_ui_to_tor_conf_info()
            bridge_line_list = self.tor_conf_info.bridge_line_list
        if not self.check_notify_sync_config_ui_result(sync_config_ui_result):
            QApplication.restoreOverrideCursor()
            return

        try:
            tcpl_write_torrc(self.tor_conf_info)
            should_restart_tor = True
        except Exception as e:
            QMessageBox.warning(
                self,
                tcp_window_title,
                f"""<p>ERROR: The Tor configuration file could not be written!
Details:</p>
<blockquote><pre>{str(e)}</pre></blockquote>""",
            )
            self.tor_conf_info = self.parse_torrc()
            ## Ensure we don't misconfigure DNS after a failed config save.
            bridge_line_list = self.tor_conf_info.bridge_line_list

        dns_adjust_result: str | None = tcpl_adjust_etc_resolv_conf(
            bridge_line_list
        )
        if isinstance(dns_adjust_result, str):
            QMessageBox.warning(
                self,
                tcp_window_title,
                f"""<p>ERROR: Gateway DNS configuration could not be adjusted!
Details:</p>
<blockquote><pre>{dns_adjust_result}</pre></blockquote>""",
            )

        self.sync_config_info()
        self.config_ui_toggle(enable_ui=False)
        if should_restart_tor:
            self.restart_tor()

        QApplication.restoreOverrideCursor()

    def cancel_configure_tor(self) -> None:
        """
        Exits out of the user configuration UI without saving changes.
        """

        self.sync_config_info()
        self.config_ui_toggle(enable_ui=False)

    def config_ui_toggle(self, enable_ui: bool) -> None:
        """
        Enables or disables the user configuration UI.
        """

        self.bridges_type_label.setVisible(not enable_ui)
        self.bridges_type_combo_box.setVisible(enable_ui)
        self.bridges_help_button.setVisible(enable_ui)
        self.proxy_type_label.setVisible(not enable_ui)
        self.proxy_type_combo_box.setVisible(enable_ui)
        self.proxy_help_button.setVisible(enable_ui)
        self.cancel_config_button.setVisible(enable_ui)
        self.enable_network_checkbox.setEnabled(enable_ui)
        if enable_ui:
            self.button_lock_dict[self.restart_tor_button].add(
                "config_ui_toggle"
            )
            self.button_lock_dict[self.stop_tor_button].add("config_ui_toggle")
        else:
            self.button_lock_dict[self.restart_tor_button].discard(
                "config_ui_toggle"
            )
            self.button_lock_dict[self.stop_tor_button].discard(
                "config_ui_toggle"
            )
        ## To avoid the button stack momentarily growing when swapping out the
        ## "Configure" and "Accept" buttons, we must always hide one first,
        ## then show the other.
        if enable_ui:
            self.configure_button.setVisible(False)
            self.accept_button.setVisible(True)
        else:
            self.accept_button.setVisible(False)
            self.configure_button.setVisible(True)
        self.show_or_hide_proxy_config(allow_show=enable_ui)
        self.sync_button_lock()

    def custom_bridges_cancel(self) -> None:
        """
        Cancel configuring custom bridges.
        """

        self.control_tab.setCurrentWidget(self.control_tab_main_page)

    # pylint: disable=too-many-locals, too-many-return-statements, too-many-branches
    def sync_config_ui_to_tor_conf_info(
        self, bridge_lines_maybe: list[str] | None = None
    ) -> SyncConfigUiResult:
        """
        Takes the settings in the configuration UI and places them into the
        tor_conf_info variable. Returns an enum value indicating either
        success, or failure and the reason for failure.
        """

        tmp_tor_conf_info: TcplTorConfInfo = copy.deepcopy(
            tcpl_blank_tor_conf_info
        )

        tmp_tor_conf_info.network_enabled = (
            self.enable_network_checkbox.isChecked()
        )

        if bridge_lines_maybe is not None and len(bridge_lines_maybe) > 0:
            tmp_tor_conf_info.bridges_enabled = True
        elif (
            self.bridges_type_combo_box.currentText()
            == tcpl_bridge_type_none_str
        ):
            tmp_tor_conf_info.bridges_enabled = False
        else:
            tmp_tor_conf_info.bridges_enabled = True
            try:
                bridges_default_json: str = tcpl_bridges_default_path.read_text(
                    encoding="utf-8"
                )
                bridges_default_dict: dict[Any, Any] = json.loads(
                    bridges_default_json
                )
            except Exception:
                QMessageBox.critical(
                    self,
                    tcp_window_title,
                    "ERROR: Could not load default bridges from "
                    + f"'{str(tcpl_bridges_default_path)}'!",
                )
                sys.exit(1)
            bridge_type: str = self.bridges_type_combo_box.currentText()
            assert bridge_type in bridges_default_dict
            bridge_list: Any = bridges_default_dict[bridge_type]
            assert isinstance(bridge_list, list)
            for bridge_str in bridge_list:
                assert isinstance(bridge_str, str)
            bridge_lines_maybe = bridge_list
        if bridge_lines_maybe is not None:
            tmp_tor_conf_info.bridge_line_list = bridge_lines_maybe
            for bridge_line in bridge_lines_maybe:
                bridge_bit_list: list[str] = bridge_line.split(" ")
                if not len(bridge_bit_list) > 1:
                    return SyncConfigUiResult.BAD_BRIDGE_LINE
                tmp_tor_conf_info.bridge_type_set.add(bridge_bit_list[1])

        proxy_type: str = self.proxy_type_combo_box.currentText()
        if proxy_type != tcpl_proxy_type_none_str:
            tmp_tor_conf_info.proxy_type = proxy_type
            proxy_host: str = self.proxy_host_line_edit.text()
            if proxy_host == "":
                return SyncConfigUiResult.PROXY_MISSING_HOST
            tmp_tor_conf_info.proxy_host = proxy_host
            proxy_port_str: str = self.proxy_port_line_edit.text()
            proxy_port: int
            if proxy_port_str == "":
                proxy_port = tcpl_default_port_for_protocol(proxy_type)
            else:
                try:
                    proxy_port = int(proxy_port_str)
                except Exception:
                    return SyncConfigUiResult.PROXY_PORT_NOT_INTEGER
            if not 1 <= proxy_port <= 65535:
                return SyncConfigUiResult.PROXY_PORT_OUT_OF_RANGE
            tmp_tor_conf_info.proxy_port = proxy_port
            proxy_username: str = self.proxy_user_line_edit.text()
            proxy_password: str = self.proxy_pass_line_edit.text()
            if proxy_username != "" or proxy_password != "":
                if proxy_type == "SOCKS4":
                    return SyncConfigUiResult.PROXY_DOES_NOT_SUPPORT_AUTH
                if proxy_type == "SOCKS5":
                    if proxy_password == "":
                        return SyncConfigUiResult.PROXY_SOCKS5_USER_WITHOUT_PASS
                    if proxy_username == "":
                        return SyncConfigUiResult.PROXY_SOCKS5_PASS_WITHOUT_USER
                    if not 1 <= len(proxy_username) <= 255:
                        return SyncConfigUiResult.PROXY_SOCKS5_USER_LEN_BAD
                    if not 1 <= len(proxy_password) <= 255:
                        return SyncConfigUiResult.PROXY_SOCKS5_PASS_LEN_BAD
                tmp_tor_conf_info.proxy_username = proxy_username
                tmp_tor_conf_info.proxy_password = proxy_password

        self.tor_conf_info = tmp_tor_conf_info
        return SyncConfigUiResult.SUCCESS

    def check_notify_sync_config_ui_result(
        self, sync_config_ui_result: SyncConfigUiResult
    ) -> bool:
        """
        Checks a SyncConfigUiResult value. Pops up an error mesasge and returns
        False if the value indicates a problem occurred.
        """

        match sync_config_ui_result:
            case SyncConfigUiResult.SUCCESS:
                return True
            case SyncConfigUiResult.BAD_BRIDGE_LINE:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: A provided custom bridge line is invalid!
Please check your custom bridge lines and try again.</p>""",
                )
            case SyncConfigUiResult.PROXY_MISSING_HOST:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: Proxy use was enabled, but no proxy server was
specified in the 'Host' field!</p>""",
                )
            case SyncConfigUiResult.PROXY_PORT_NOT_INTEGER:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: The proxy port specified in the 'Port' field
is not an integer!</p>""",
                )
            case SyncConfigUiResult.PROXY_PORT_OUT_OF_RANGE:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: The proxy port specified in the 'Port' field
is out of range! It must be between 1 and 65535 inclusive.</p>""",
                )
            case SyncConfigUiResult.PROXY_DOES_NOT_SUPPORT_AUTH:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: The specified proxy type does not support
authentication! Please clear the 'User' and 'Pass' fields and try
again.</p>""",
                )
            case SyncConfigUiResult.PROXY_SOCKS5_USER_WITHOUT_PASS:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: A proxy username was provided, but no
password! SOCKS5 requires both when authenticating.""",
                )
            case SyncConfigUiResult.PROXY_SOCKS5_PASS_WITHOUT_USER:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: A proxy password was provided, but no
username! SOCKS5 requires both when authenticating.""",
                )
            case SyncConfigUiResult.PROXY_SOCKS5_USER_LEN_BAD:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: The proxy username's length is out of range!
It must be between 1 and 255 characters long.""",
                )
            case SyncConfigUiResult.PROXY_SOCKS5_PASS_LEN_BAD:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    """<p>ERROR: The proxy password's length is out of range!
It must be between 1 and 255 characters long.""",
                )

        return False

    def show_onion_circuits(self) -> None:
        """
        Opens the Onion Circuits app.
        """

        # pylint: disable=consider-using-with
        subprocess.Popen(["onioncircuits"])

    def send_newnym(self) -> None:
        """
        Sends a NEWNYM message to Tor.
        """

        try:
            with Controller.from_socket_file(
                str(tcpl_tor_control_path)
            ) as tor_controller:
                tor_controller.authenticate(str(tcpl_tor_auth_path))
                ## Signal.NEWNYM exists but pylint can't see it.
                # pylint: disable=no-member
                tor_controller.signal(Signal.NEWNYM)
                QMessageBox.information(
                    self,
                    tcp_window_title,
                    """<p>INFO: NEWNYM message sent to Tor.</p>""",
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                tcp_window_title,
                f"""<p>ERROR: Could not send NEWNYM message to Tor!
Details:</p>

<blockquote><pre>{sanitize_string(str(e))}</pre></blockquote>""",
            )

    def load_logs(self) -> None:
        """
        Displays the appropriate log data depending on which one of the log
        radio buttons is checked.
        """

        wait_cursor: QCursor = QCursor(Qt.CursorShape.WaitCursor)
        QApplication.setOverrideCursor(wait_cursor)

        self.logs_text_edit.clear()
        display_text: str | None = None
        if self.logs_torrc_radio_button.isChecked():
            try:
                display_text = tcpl_torrc_file.read_text(encoding="utf-8")
            except Exception as e:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    f"""<p>ERROR: Could not read '{str(tcpl_torrc_file)}'!
Details:</p>

<blockquote><pre>{sanitize_string(str(e))}</pre></blockquote>""",
                )
        elif self.logs_tor_log_radio_button.isChecked():
            ## We could implement the equivalent of `tail` in Python here, but
            ## just using `tail` is easier and probably faster.
            tor_log_info: subprocess.CompletedProcess[str] = subprocess.run(
                ["/usr/bin/tail", "--lines=3000", "--", tcpl_tor_log_path],
                check=False,
                capture_output=True,
                encoding="utf-8",
            )
            if tor_log_info.returncode != 0:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    f"""<p>ERROR: Could not read Tor log! Details:</p>

<blockquote><pre>{sanitize_string(
    tor_log_info.stdout + tor_log_info.stderr
)}</pre></blockquote>""",
                )
                return
            display_text = tor_log_info.stdout
        elif self.logs_systemd_journal_radio_button.isChecked():
            tor_journal_info: subprocess.CompletedProcess[str] = (
                tcpl_run_privileged_task_sync(
                    "tor-control-panel-read-tor-default-log"
                )
            )
            if tor_journal_info.returncode != 0:
                QMessageBox.warning(
                    self,
                    tcp_window_title,
                    f"""<p>ERROR: Could not get Tor-related journal logs!
Details:</p>
<blockquote><pre>{sanitize_string(
    tor_journal_info.stdout + tor_journal_info.stderr
)}</pre></blockquote>""",
                )
                return
            display_text = tor_journal_info.stdout
        else:
            QMessageBox.warning(
                self,
                tcp_window_title,
                """<p>ERROR: No Tor log radio button is checked! Please report
this bug!</p>""",
            )

        if display_text is not None:
            self.logs_text_edit.setPlainText(display_text)
            self.logs_text_edit.moveCursor(QTextCursor.MoveOperation.End)

        QApplication.restoreOverrideCursor()


class SplashScreenDialog(QDialog):
    """
    Shows a simple splash screen while Tor config sanity is being checked.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setGeometry(QRect(0, 0, 350, 75))
        self.setWindowTitle(tcp_window_title)
        self.root_layout: QVBoxLayout = QVBoxLayout()
        self.splash_label: QLabel = QLabel()
        self.splash_label.setWordWrap(True)
        self.splash_label.setText("Tor Control Panel is starting...")
        self.progress_bar: QProgressBar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)
        self.root_layout.addWidget(self.splash_label)
        self.root_layout.addStretch()
        self.root_layout.addWidget(self.progress_bar)
        self.setLayout(self.root_layout)


# pylint: disable=too-few-public-methods
class TorSanityChecker(QObject):
    """
    Checks if Tor config is sane. Intended to run in a secondary thread.
    """

    torConfigSane = pyqtSignal()
    torConfigNotSane = pyqtSignal(str)

    def run(self) -> None:
        """
        Core function, launched by thread.
        """

        tor_config_is_sane: bool
        tor_config_sane_output: str | None
        tor_config_is_sane, tor_config_sane_output = tcpl_tor_config_sane()

        if not tor_config_is_sane:
            assert tor_config_sane_output is not None
            self.torConfigNotSane.emit(sanitize_string(tor_config_sane_output))
        else:
            self.torConfigSane.emit()


class AppInitManager(QObject):
    """
    Displays a splash screen if needed, checks Tor config sanity, then displays
    the main UI or an error message as appropriate.
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)

        self.main_window: TorControlPanelDialog | None = None
        self.splash_window: SplashScreenDialog | None = None
        self.should_show_splash: bool = True

        self.splash_display_timer: QTimer = QTimer()
        self.splash_display_timer.setInterval(500)
        self.splash_display_timer.setSingleShot(True)
        self.splash_display_timer.timeout.connect(self.show_splash_screen)
        self.splash_display_timer.start()

        self.tor_sanity_checker: TorSanityChecker = TorSanityChecker()
        self.checker_thread: QThread = QThread()
        self.tor_sanity_checker.torConfigSane.connect(self.start_main_ui)
        self.tor_sanity_checker.torConfigNotSane.connect(self.show_check_error)
        self.tor_sanity_checker.moveToThread(self.checker_thread)
        self.checker_thread.started.connect(self.tor_sanity_checker.run)
        self.checker_thread.start()

    def show_splash_screen(self) -> None:
        """
        Displays the splash screen when the corresponding timer triggers. This
        lets us skip showing the screen if the sanity check ends up being fast.
        """

        ## Guard against a possible race between splash_display_timer and
        ## tor_sanity_checker.
        if self.should_show_splash:
            self.splash_window = SplashScreenDialog()
            self.splash_window.show()

    def cleanup_splash_and_checker(self) -> None:
        """
        Closes the splash screen or prevents it from popping up. Also
        terminates the checker thread.
        """

        if self.splash_window is not None:
            self.splash_window.close()
            del self.splash_window
        else:
            self.splash_display_timer.stop()
        self.should_show_splash = False

        self.checker_thread.quit()

    def start_main_ui(self) -> None:
        """
        Switches to the main UI.
        """

        self.cleanup_splash_and_checker()
        self.main_window = TorControlPanelDialog()
        self.main_window.show()

    def show_check_error(self, error_msg: str) -> None:
        """
        Displays an error message and aborts the application if Tor config is
        not sane.
        """

        self.cleanup_splash_and_checker()
        QMessageBox.critical(
            None,
            tcp_window_title,
            f"""<p>ERROR: Tor config is not sane! Details:</p>
<blockquote><pre>{error_msg}</pre></blockquote>""",
        )
        sys.exit(1)


def open_link_maybe(link: str, parent: QWidget | None = None) -> None:
    """
    If running under Whonix-Gateway, displays a popup with isntructions on how
    to open a link somewhere else. Otherwise, opens the link in the user's
    default web browser.
    """

    if whonix_gw_flag_file.is_file():
        QMessageBox.information(
            parent,
            tcp_window_title,
            f"""<p>INFO: Whonix-Gateway cannot open links. Copy or type the
following URL into a web browser on a Whonix-Workstation machine:</p>

<b>{link}</b>""",
        )
    else:
        QDesktopServices.openUrl(QUrl(link))


# pylint: disable=unused-argument
def signal_handler(sig: int, frame: FrameType | None) -> None:
    """
    Handles SIGINT and SIGTERM.
    """

    print("Received SIGINT or SIGTERM, exiting.", file=sys.stderr)
    sys.exit(128 + sig)


def main() -> NoReturn:
    """
    Main function.
    """

    if os.geteuid() == 0:
        print(
            "ERROR: Do not run Tor Control Panel with sudo / as root!",
            file=sys.stderr,
        )
        sys.exit(1)

    app: QApplication = QApplication(sys.argv)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timer: QTimer = QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    # pylint: disable=unused-variable
    app_init_manager: AppInitManager = AppInitManager()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
