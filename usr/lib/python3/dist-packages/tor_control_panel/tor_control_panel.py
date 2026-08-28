#!/usr/bin/python3 -Bsu

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import signal

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from subprocess import Popen, PIPE

import os

from sanitize_string.sanitize_string_lib import sanitize_string

from . import tor_status, tor_bootstrap, torrc_gen, info, info_gui, validators, privilege
from .command_thread import run_async as _run_async, wait_for_commands


def ensure_debian_tor_group_access(parent):
    """Prompt (plain Debian only) to add the account to the debian-tor group.

    On plain Debian the Tor control socket + cookie are accessible only to the
    debian-tor group, so the desktop account must be a member for either GUI to
    reach Tor. On Whonix anon-gw-anonymizer-config already does this, so skip.
    Shows the exact privileged command before running it, then tells the user a
    re-login is needed (group membership only applies at login). `parent` is the
    QWidget to parent the dialogs to.
    """
    if tor_status.whonix:
        return
    if tor_status.user_in_debian_tor_group():
        return
    try:
        command_display = ' '.join(privilege.command('add-tor-group'))
    except privilege.NoPrivilegeMethod:
        ## No escalation method available; nothing we can offer to run.
        return

    import getpass
    current_user = getpass.getuser()
    reply = QMessageBox.question(
        parent, 'Grant Tor control access',
        'tor-control-panel needs to add your desktop account to the '
        "'debian-tor' group so it can reach Tor's control port.\n\n"
        'The following command will be run, with administrator '
        'authentication:\n\n    ' + command_display + '\n\n'
        "It auto-detects and adds your desktop account (currently '"
        + current_user + "') to the 'debian-tor' group. Proceed?",
        QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
    if reply != QMessageBox.Yes:
        return

    if privilege.run('add-tor-group') == 0:
        QMessageBox.information(
            parent, 'Re-login required',
            "Your account was added to the 'debian-tor' group.\n\n"
            'Please re-login or reboot for the change to take effect.')
    else:
        QMessageBox.warning(
            parent, 'Could not grant access',
            "Adding your account to the 'debian-tor' group failed. You can do "
            'it manually:\n\n    sudo adduser ' + current_user + ' debian-tor')


class TorControlPanel(QDialog):
    def __init__(self):
        super(TorControlPanel, self).__init__()

        ## Make sure the torrc drop-in / includes exist. Dispatched through the
        ## privilege runner so it uses leaprun on Whonix/Kicksecure and pkexec
        ## on a plain-Debian system.
        privilege.run('tor-config-sane')

        ## Plain Debian: make sure the account can reach Tor's control socket.
        ensure_debian_tor_group_access(self)

        self.setMinimumSize(650, 465)

        icons_path = '/usr/share/tor-control-panel/'
        self.refresh_icon = QtGui.QIcon(icons_path + 'refresh.png')
        self.exit_icon = QtGui.QIcon(icons_path + 'Exit.png')

        self.restart_icon = QtGui.QIcon(icons_path + 'restart.png')
        self.stop_icon = QtGui.QIcon(icons_path + 'stop.png')
        self.tool_icon = QtGui.QIcon(icons_path + 'tools.png')
        self.info_icon = QtGui.QIcon(icons_path + 'help.png')
        self.back_icon = QtGui.QIcon(icons_path + 'prev.png')
        self.accept_icon = QtGui.QIcon(icons_path + 'accept_icon.png')
        self.onions_icon = QtGui.QIcon(icons_path + 'onion.png')
        self.newid_icon = QtGui.QIcon(icons_path + 'newnym.png')

        self.tor_status_color = ['green', '#AF0000', '#AF0000', 'orange',
                                 'orange', '#AF0000']
        self.tor_status_list = ['running', 'stopped', 'disabled',
                                'disabled-running', 'acquiring', 'no_controller']

        self.message = ''
        self.tor_message = info.tor_stopped()
        self.tor_running_path = '/run/tor/tor.pid'
        self.torrc_file_path = torrc_gen.torrc_path()

        try:
            self.journal_command = privilege.command(
                'tor-control-panel-read-tor-default-log')
        except privilege.NoPrivilegeMethod:
            ## No escalation method on this system. The journal view is one
            ## optional log source, so degrade to disabling it -- raising here
            ## would abort __init__ and take the whole GUI down with a
            ## traceback before the window ever appears.
            self.journal_command = None

        ## Built from torrc_gen's canonical lists (prefixed with 'None') so the
        ## bridge/proxy type strings cannot drift out of sync with what
        ## gen_torrc()/parse_torrc() expect.
        self.bridges = ['None'] + torrc_gen.bridge_types
        self.default_bridges = ['None'] + torrc_gen.default_bridge_types
        self.proxies = ['None'] + torrc_gen.proxies

        self.use_default_bridges = False
        self.use_custom_bridges = False
        self.use_proxy = False

        self.tor_log = '/run/tor/log'

        # tor log HTML style
        self.warn_style = '<span style="background-color:yellow">{}' \
            .format('[warn]')
        self.error_style = '<span style="background-color:red">{}' \
            .format('[error]')

        # Declared here (not where it is shown) so the message box is modal.
        self.invalid_custom_bridges_box = QMessageBox(QMessageBox.Warning, 'Warning',
                                                    info.invalid_custom_bridges(), QMessageBox.Ok)

        self.invalid_proxy_box = QMessageBox(QMessageBox.Warning, 'Warning',
                                    info.invalid_ip_port(), QMessageBox.Ok)

        self.bootstrap_done = True

        self.tabs = QTabWidget()
        self.control_tab = QWidget()
        self.logs_tab = QWidget()
        self.utils_tab = QWidget()

        self.button_layout = QHBoxLayout()
        self.quit_button = QPushButton(self.exit_icon, ' Exit')
        self.quit_button.clicked.connect(self.quit)

        self.button_layout.addWidget(self.quit_button)
        self.button_layout.setAlignment(Qt.AlignRight)

        self.layout = QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.tabs)
        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

        self.control_tab_layout = QVBoxLayout(self.control_tab)
        self.info_frame = QFrame()
        self.info_layout = QGridLayout(self.info_frame)
        self.info_layout.setAlignment(Qt.AlignTop)

        self.status = QPushButton()
        self.status.setEnabled(False)
        self.info_layout.addWidget(self.status, 0, 0, 1, 1)
        self.tor_message_browser = QTextBrowser()
        self.info_layout.addWidget(self.tor_message_browser, 0, 1, 2, 1)
        self.bootstrap_progress = QtWidgets.QProgressBar()
        self.info_layout.addWidget(self.bootstrap_progress, 1, 1, 1, 1)

        self.user_frame = QFrame()
        self.user_layout = QHBoxLayout(self.user_frame)
        self.config_group_box = QGroupBox()

        self.bridges_heading_label = QLabel()
        self.bridge_type = QLabel()
        self.bridges_combo = QComboBox()
        for bridge in self.bridges:
            self.bridges_combo.addItem(bridge)
        self.bridges_combo.insertSeparator(1)
        self.bridges_combo.insertSeparator(7)
        self.bridges_combo.addItem('Disable network')
        self.bridge_info_button = QPushButton(self.info_icon, '')
        self.bridge_info_button.clicked.connect(info_gui.show_help_censorship)

        self.proxy_heading_label = QLabel()
        self.proxy_type = QLabel()
        self.proxy_combo = QComboBox()
        for proxy in self.proxies:
            self.proxy_combo.addItem(proxy)
        self.proxy_combo.insertSeparator(1)
        self.proxy_combo.currentIndexChanged.connect(
            lambda: self.update_proxy_settings(self.proxy_combo.currentText()))

        self.proxy_info_button = QPushButton(self.info_icon, '')
        self.proxy_info_button.clicked.connect(info_gui.show_proxy_help)

        self.config_grid_layout = QGridLayout()
        self.config_grid_layout.addWidget(self.bridges_heading_label, 0, 0)
        self.config_grid_layout.addWidget(self.bridge_type, 0, 1)
        self.config_grid_layout.addWidget(self.bridges_combo, 0, 1)
        self.config_grid_layout.addWidget(self.bridge_info_button, 0, 2)
        self.config_grid_layout.addWidget(self.proxy_heading_label, 1, 0)
        self.config_grid_layout.addWidget(self.proxy_type, 1, 1)
        self.config_grid_layout.addWidget(self.proxy_combo, 1, 1)
        self.config_grid_layout.addWidget(self.proxy_info_button, 1, 2)
        self.config_grid_layout.setAlignment(Qt.AlignTop)
        self.config_grid_layout.setVerticalSpacing(6)

        self.proxy_ip_label = QLabel()
        self.proxy_ip_edit = QLineEdit()
        self.proxy_port_label = QLabel()
        self.proxy_port_edit = QLineEdit()

        self.proxy_user_label = QLabel()
        self.proxy_user_edit = QLineEdit()
        self.proxy_pwd_label = QLabel()
        self.proxy_pwd_edit = QLineEdit()

        self.prev_button = QPushButton(self.back_icon, '')
        self.prev_button.clicked.connect(self.exit_configuration)

        self.proxy_settings_layout = QGridLayout()
        self.proxy_settings_layout.addWidget(self.proxy_ip_label, 0, 0)
        self.proxy_settings_layout.addWidget(self.proxy_ip_edit, 0, 1)
        self.proxy_settings_layout.addWidget(self.proxy_port_label, 0, 2)
        self.proxy_settings_layout.addWidget(self.proxy_port_edit, 0, 3)
        self.proxy_settings_layout.addWidget(self.proxy_user_label, 1, 0)
        self.proxy_settings_layout.addWidget(self.proxy_user_edit, 1, 1)
        self.proxy_settings_layout.addWidget(self.proxy_pwd_label, 1, 2)
        self.proxy_settings_layout.addWidget(self.proxy_pwd_edit, 1, 3)
        self.proxy_settings_layout.addWidget(self.prev_button, 1, 4)
        self.proxy_settings_layout.setAlignment(Qt.AlignRight)

        self.config_layout = QVBoxLayout(self.config_group_box)
        self.config_layout.addLayout(self.config_grid_layout)
        self.config_layout.addLayout(self.proxy_settings_layout)

        self.user_layout.addWidget(self.config_group_box)

        self.control_box = QGroupBox()
        self.restart_button = QPushButton(self.restart_icon, ' Restart Tor',
                                          self.control_box)
        self.stop_button = QPushButton(self.stop_icon, ' Stop Tor',
                                       self.control_box)
        self.configure_button = QPushButton(self.tool_icon, ' Configure',
                                            self.control_box)

        self.restart_button.clicked.connect(self.restart_tor)
        self.stop_button.clicked.connect(self.stop_tor)
        self.configure_button.clicked.connect(self.configure)

        self.user_layout.addWidget(self.control_box)

        self.control_tab_layout.addWidget(self.info_frame)
        self.control_tab_layout.addWidget(self.user_frame)

        self.logs_tab_layout = QVBoxLayout(self.logs_tab)
        self.view_layout = QHBoxLayout()

        self.view_frame = QFrame()
        self.view_frame.setMinimumHeight(105)
        self.files_box = QGroupBox(self.view_frame)
        self.refresh_button = QPushButton(self.refresh_icon, ' Refresh')
        self.view_layout.setAlignment(Qt.AlignTop)
        self.view_layout.addWidget(self.view_frame)
        self.view_layout.addWidget(self.refresh_button)

        ## Real column-header labels instead of space-padding the group-box
        ## title (which breaks under a different font). Radio buttons are added
        ## to files_box_layout below, which reparents them, so they need no
        ## explicit parent here.
        self.files_box_layout = QGridLayout(self.files_box)
        self.files_header = QLabel('Files')
        self.logs_header = QLabel('Logs')
        self.torrc_button = QRadioButton()
        self.log_button = QRadioButton()
        self.journal_button = QRadioButton()
        self.files_box_layout.addWidget(self.files_header, 0, 0)
        self.files_box_layout.addWidget(self.logs_header, 0, 1)
        self.files_box_layout.addWidget(self.torrc_button, 1, 0)
        self.files_box_layout.addWidget(self.log_button, 1, 1)
        self.files_box_layout.addWidget(self.journal_button, 2, 1)

        self.torrc_button.toggled.connect(self.refresh_logs)
        self.log_button.toggled.connect(self.refresh_logs)
        self.journal_button.toggled.connect(self.refresh_logs)
        self.refresh_button.clicked.connect(self.refresh_logs)

        self.file_browser = QTextBrowser()
        self.file_browser.setLineWrapMode(QTextBrowser.NoWrap)

        self.logs_tab_layout.addLayout(self.view_layout)
        self.logs_tab_layout.addWidget(self.file_browser)

        self.custom_bridges_frame = QFrame(self.control_tab)
        self.custom_bridges_layout = QVBoxLayout(self.custom_bridges_frame)
        self.custom_bridges_help = QLabel(self.custom_bridges_frame)
        self.custom_bridges = QtWidgets.QTextEdit(self.custom_bridges_frame)
        self.custom_bridges_layout.addWidget(self.custom_bridges_help)
        self.custom_bridges_layout.addWidget(self.custom_bridges)
        self.custom_bridges.setLineWrapMode(QTextEdit.NoWrap)

        self.custom_bridges_button_layout = QHBoxLayout()
        self.custom_cancel_button = QPushButton(QtGui.QIcon(
            self.back_icon), 'Cancel', self.custom_bridges_frame)
        self.custom_cancel_button.clicked.connect(self.close_custom_bridges)
        self.custom_accept_button = QPushButton(QtGui.QIcon(
            self.accept_icon), 'Accept', self.custom_bridges_frame)
        self.custom_accept_button.clicked.connect(self.accept_custom_bridges)
        self.custom_bridges_button_layout.addWidget(self.custom_cancel_button)
        self.custom_bridges_button_layout.addWidget(self.custom_accept_button)
        self.custom_bridges_button_layout.setAlignment(Qt.AlignRight)
        self.custom_bridges_layout.addLayout(self.custom_bridges_button_layout)

        self.control_tab_layout.addWidget(self.custom_bridges_frame)

        self.utils_tab_layout = QtWidgets.QVBoxLayout(self.utils_tab)

        self.onioncircuits_box = QFrame()
        self.onions_layout = QVBoxLayout(self.onioncircuits_box)
        self.onioncircuits_button = QPushButton(self.onions_icon,
                                                ' Onion &Circuits')
        self.onioncircuits_button.clicked.connect(self.onioncircuits)
        self.onions_label = QLabel()
        self.onions_layout.addWidget(self.onioncircuits_button)
        self.onions_layout.addWidget(self.onions_label)

        self.newnym_box = QFrame()
        self.newnym_layout = QVBoxLayout(self.newnym_box)
        self.newnym_button = QPushButton(self.newid_icon, ' Request new Tor circuit ')
        self.newnym_button.clicked.connect(self.newnym)
        self.newnym_label = QLabel()
        self.newnym_layout.addWidget(self.newnym_button)
        self.newnym_layout.addWidget(self.newnym_label)
        self.dummy1 = QFrame()
        self.dummy2 = QFrame()

        self.utils_tab_layout.addWidget(self.onioncircuits_box)
        self.utils_tab_layout.addWidget(self.newnym_box)
        self.utils_tab_layout.addWidget(self.dummy1)
        self.utils_tab_layout.addWidget(self.dummy2)

        self.newnym_box.setFrameShape(QFrame.Panel | QFrame.Raised)
        self.onioncircuits_box.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.setup_ui()

    def setup_ui(self):
        self.tabs.addTab(self.control_tab, 'Control')
        self.tabs.addTab(self.utils_tab, 'Utilities')
        self.tabs.addTab(self.logs_tab, 'Logs')

        self.quit_button.setIconSize(QtCore.QSize(20, 20))

        self.status.setText('Tor status')

        self.tor_message_browser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.tor_message_browser.setMinimumHeight(24)
        self.tor_message_browser.setStyleSheet('background-color:rgba(0, 0, 0, 0)')

        self.bootstrap_progress.setMaximumHeight(15)
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)
        self.bootstrap_progress.hide()

        self.user_frame.setLineWidth(2)
        self.user_frame.setMaximumHeight(175)
        self.user_frame.setMinimumHeight(175)
        self.user_frame.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.config_group_box.setTitle('User configuration')

        self.bridges_heading_label.setMaximumWidth(90)
        self.bridges_heading_label.setText('Bridges type :')
        self.bridge_type.setStyleSheet('font:bold')
        self.bridge_type.setMinimumHeight(24)
        self.bridges_combo.hide()
        self.bridge_info_button.setMaximumWidth(20)
        self.bridge_info_button.setFlat(True)
        self.bridge_info_button.hide()
        self.bridge_info_button.setToolTip('Show bridges help')

        self.proxy_heading_label.setText('Proxy type :')
        self.proxy_heading_label.setMaximumWidth(90)
        self.proxy_type.setStyleSheet('font:bold')
        self.proxy_type.setMinimumHeight(24)
        self.proxy_combo.hide()
        self.proxy_info_button.setMaximumWidth(20)
        self.proxy_info_button.setFlat(True)
        self.proxy_info_button.hide()
        self.proxy_info_button.setToolTip('Show proxies help')

        self.proxy_ip_label.setText('Address:')
        self.proxy_ip_label.hide()
        self.proxy_ip_edit.setPlaceholderText('ex : 127.0.0.1')
        self.proxy_ip_edit.hide()
        self.proxy_ip_edit.setEnabled(False)

        self.proxy_port_label.setText('Port:')
        self.proxy_port_label.hide()
        self.proxy_port_edit.setPlaceholderText('1-65535')
        self.proxy_port_edit.hide()
        self.proxy_port_edit.setEnabled(False)

        self.proxy_user_label.setText('User: ')
        self.proxy_user_label.hide()
        self.proxy_user_edit.setPlaceholderText('Optional')
        self.proxy_user_edit.hide()
        self.proxy_user_edit.setEnabled(False)

        self.proxy_pwd_label.setText('Password: ')
        self.proxy_pwd_label.hide()
        self.proxy_pwd_edit.setPlaceholderText('Optional')
        self.proxy_pwd_edit.hide()
        self.proxy_pwd_edit.setEnabled(False)

        self.prev_button.setMaximumWidth(20)
        self.prev_button.setFlat(True)
        self.prev_button.hide()
        self.prev_button.setToolTip('Quit configuration')

        self.control_box.setMinimumWidth(140)
        self.control_box.setMaximumWidth(140)
        self.control_box.setTitle('Control')
        self.restart_button.setIconSize(QtCore.QSize(28, 28))
        self.restart_button.setFlat(True)
        self.stop_button.setIconSize(QtCore.QSize(28, 28))
        self.stop_button.setFlat(True)
        self.configure_button.setIconSize(QtCore.QSize(28, 28))
        self.configure_button.setFlat(True)
        self.configure_button.setDefault(True)

        ## Stack the Control buttons in a layout instead of absolute
        ## setGeometry, so the group box sizes itself and the buttons stay put
        ## when fonts / DPI differ.
        self.control_box_layout = QVBoxLayout(self.control_box)
        self.control_box_layout.setAlignment(Qt.AlignTop)
        self.control_box_layout.addWidget(self.restart_button)
        self.control_box_layout.addWidget(self.stop_button)
        self.control_box_layout.addWidget(self.configure_button)

        self.custom_bridges_frame.hide()
        self.custom_cancel_button.setFlat(True)
        self.custom_accept_button.setFlat(True)
        self.custom_bridges_help.setWordWrap(True)
        self.custom_bridges_help.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.custom_bridges_help.setText(info.tcp_custom_bridges_help())

        self.newnym_box.setMaximumHeight(130)
        self.newnym_button.setMaximumWidth(175)
        self.newnym_button.setIconSize(QtCore.QSize(18, 18))
        self.newnym_label.setWordWrap(True)
        self.newnym_label.setTextFormat(Qt.RichText)
        self.newnym_label.setText(info.newnym_text())

        self.onioncircuits_box.setMaximumHeight(80)
        self.onioncircuits_button.setMaximumWidth(120)
        self.onioncircuits_button.setIconSize(QtCore.QSize(20, 20))
        self.onions_label.setWordWrap(True)
        self.onions_label.setText(info.onions_text())

        self.files_box_layout.setVerticalSpacing(0)
        self.files_box_layout.setHorizontalSpacing(20)
        self.files_box_layout.setContentsMargins(6, 0, 6, 0)
        self.files_box.setTitle('View')
        self.torrc_button.setText('&torrc')
        self.log_button.setText('Tor &log')
        self.journal_button.setText('systemd &journal')
        self.log_button.setChecked(True)

        self.refresh_button.setMaximumWidth(70)
        self.refresh_button.setFlat(True)

    def newnym(self):
        import socket
        import stem
        ## Explicit: 'import stem' alone does not bind the submodule, and the
        ## except clause below names stem.connection.AuthenticationFailure.
        import stem.connection
        from stem import Signal
        from stem.control import Controller

        control_socket_path = '/run/tor/control'

        ## Pre-flight the connection with our own socket (closed by the context
        ## manager either way). stem's from_socket_file leaks the underlying fd
        ## when the connect fails -- ControlSocketFile._make_socket() creates the
        ## socket, and if connect() raises the socket is never closed -- so only
        ## hand the path to stem once we know a connection succeeds.
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(control_socket_path)
        except OSError:
            print('NEWNYM: cannot connect to the Tor control socket')
            return

        try:
            with Controller.from_socket_file(control_socket_path) as controller:
                controller.authenticate()
                ## controller.signal() is synchronous: it returns only after
                ## Tor's '250 OK', so the NEWNYM has already been accepted here.
                ## Do NOT restart Tor afterwards -- a restart would tear down the
                ## very circuits NEWNYM just requested (and drop every existing
                ## connection), which defeats a lightweight 'new circuit' request
                ## (arraybolt3 review: "do we know Tor processed NEWNYM before we
                ## restart?" -- yes, and restarting negates it).
                controller.signal(Signal.NEWNYM)
        except stem.SocketError:
            print('NEWNYM: cannot connect to the Tor control socket')
        except stem.UnsatisfiableRequest:
            print('NEWNYM: signal failed to be processed')
        except stem.connection.AuthenticationFailure:
            ## authenticate() raises AuthenticationFailure subclasses
            ## (MissingAuthenticationInfo, UnreadableCookieFile,
            ## IncorrectCookieValue), none of which are SocketError. On plain
            ## Debian an account not yet in 'debian-tor' cannot read the
            ## control cookie and lands here, so letting it escape the clicked
            ## slot printed a traceback instead of the message.
            print('NEWNYM: cannot authenticate to the Tor control socket')

    def onioncircuits(self):
        ## Launch the separate Onion Circuits viewer; Popen does not wait, so it
        ## runs alongside the panel without a shell or a trailing '&'.
        Popen(['onioncircuits'])

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        self.bootstrap_progress.show()
        self.bootstrap_progress.setValue(bootstrap_percent)
        self.bootstrap_done = False
        self.message = bootstrap_phase

        if bootstrap_percent == 100:
            self.bootstrap_progress.hide()
            self.restart_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.refresh(False)
            self.bootstrap_done = True
        else:
            self.tor_status = 'acquiring'
            self.refresh_status()

        if bootstrap_phase == 'no_controller':
            self.stop_bootstrap_thread()
            self.tor_status = 'no_controller'
            self.message = info.no_controller()
            self.bootstrap_progress.hide()
            self.restart_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.refresh_status()

        elif bootstrap_phase == 'socket_error':
            self.stop_bootstrap_thread()
            self.message = info.socket_error()
            self.bootstrap_progress.hide()
            self.control_box.setEnabled(True)
            self.refresh_status()

        elif bootstrap_phase == 'cookie_authentication_failed':
            self.stop_bootstrap_thread()
            self.message = info.cookie_error()
            self.bootstrap_progress.hide()
            self.control_box.setEnabled(True)
            self.refresh_status()

    def run_async(self, func, on_done):
        ## Run a blocking privileged operation off the GUI thread so the window
        ## does not freeze (e.g. Enable network's leaprun restart/reload/status).
        ## on_done(result) runs back on the GUI thread when func returns.
        return _run_async(self, func, on_done)

    def privileged_argv(self, action, *args):
        """argv for a privileged helper, or None after telling the user why.

        Every GUI ACTION goes through this. privilege.command() raises
        NoPrivilegeMethod when leaprun, pkexec and passwordless sudo are all
        absent, and an unguarded call raises straight out of a clicked slot as
        a traceback instead of a message. Centralised so a call site added
        later cannot quietly reintroduce that.
        """
        try:
            return privilege.command(action, *args)
        except privilege.NoPrivilegeMethod:
            QMessageBox.critical(
                self, 'No privilege escalation method',
                'This action needs administrator rights, but none of '
                'privleap, pkexec or passwordless sudo is available.')
            return None

    def _after_enable_network(self):
        ## GUI-thread continuation after set_enabled() finished off-thread.
        self.restart_tor()
        self.exit_configuration()

    def stop_bootstrap_thread(self):
        ## Guard against a terminate() before start_bootstrap() ever created the
        ## thread, which would otherwise raise AttributeError.
        if getattr(self, 'bootstrap_thread', None):
            self.bootstrap_thread.terminate()
            ## terminate() is asynchronous; wait so callers (restart / quit) do
            ## not proceed while the old QThread is still shutting down.
            self.bootstrap_thread.wait()

    def start_bootstrap(self):
        self.bootstrap_thread = tor_bootstrap.TorBootstrap(self)
        self.bootstrap_thread.signal.connect(self.update_bootstrap)
        self.bootstrap_thread.start()

    def close_custom_bridges(self):
        self.status.show()
        self.tor_message_browser.show()
        self.user_frame.show()
        self.custom_bridges_frame.hide()
        self.exit_configuration()

    def check_valid_custom_bridges(self):
        return validators.valid_custom_bridges(self.custom_bridges.toPlainText())

    def accept_custom_bridges(self):
        if not self.check_valid_custom_bridges():
             self.invalid_custom_bridges_box.setWindowModality(QtCore.Qt.WindowModal)
             self.invalid_custom_bridges_box.exec_()
             return

        else:
            self.close_custom_bridges()
            self.set_torrc()

    def check_valid_proxy_settings(self):
        return (validators.valid_ip(self.proxy_ip_edit.text()) and
                validators.valid_port(self.proxy_port_edit.text()) and
                validators.valid_proxy_credential(self.proxy_user_edit.text()) and
                validators.valid_proxy_credential(self.proxy_pwd_edit.text()))

    def update_proxy_settings(self, proxy):
        if proxy == 'None':
            self.proxy_ip_label.hide()
            self.proxy_ip_edit.hide()
            self.proxy_port_label.hide()
            self.proxy_port_edit.hide()
            self.proxy_user_label.hide()
            self.proxy_user_edit.hide()
            self.proxy_pwd_label.hide()
            self.proxy_pwd_edit.hide()
        else:
            self.proxy_ip_label.show()
            self.proxy_ip_edit.show()
            self.proxy_port_label.show()
            self.proxy_port_edit.show()
            self.proxy_user_label.show()
            self.proxy_user_edit.show()
            self.proxy_pwd_label.show()
            self.proxy_pwd_edit.show()
            enable_auth = (proxy != 'SOCKS4') and \
                          ('Accept' in self.configure_button.text())
            self.proxy_user_edit.setEnabled(enable_auth)
            self.proxy_pwd_edit.setEnabled(enable_auth)

    def configure(self):
        if 'Configure' in self.configure_button.text():
            self.configure_button.setText(' Accept    ')
            self.configure_button.setIcon(self.accept_icon)
            self.restart_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.bridges_combo.show()
            self.proxy_combo.show()
            self.proxy_ip_edit.setEnabled(True)
            self.proxy_port_edit.setEnabled(True)
            self.proxy_user_edit.setEnabled(True)
            self.proxy_pwd_edit.setEnabled(True)
            self.update_proxy_settings(self.proxy_combo.currentText())
            self.bridge_info_button.show()
            self.proxy_info_button.show()
            self.prev_button.show()

            bridge = self.bridge_type.text()
            index = self.bridges_combo.findText(bridge, QtCore.Qt.MatchFixedString)
            self.bridges_combo.setCurrentIndex(index)

            proxy = self.proxy_type.text()
            index = self.proxy_combo.findText(proxy, QtCore.Qt.MatchFixedString)
            self.proxy_combo.setCurrentIndex(index)
            self.update_proxy_settings(proxy)

        elif 'Accept' in self.configure_button.text():
            if self.bridges_combo.currentText() in self.default_bridges:
                self.use_default_bridges = True
                self.use_custom_bridges = False

            elif self.bridges_combo.currentText() == 'Custom bridges':
                self.status.hide()
                self.tor_message_browser.hide()
                self.user_frame.hide()

                ## Retrieve custom bridges (sanitized; shared with the wizard).
                ## Clear unconditionally so stale bridges from a previous view
                ## do not linger when the current torrc has none.
                self.custom_bridges.clear()
                for line in torrc_gen.read_custom_bridge_lines(
                        self.torrc_file_path):
                    self.custom_bridges.append(line)
                self.custom_bridges.moveCursor(QtGui.QTextCursor.Start)

                self.custom_bridges_frame.show()
                self.use_custom_bridges = True
                self.use_default_bridges = False

            elif self.bridges_combo.currentText() == 'Disable network':
                ## A network toggle is a TERMINAL action: launch it and stop.
                ## Falling through re-read tor_status() BEFORE this async
                ## set_disabled had rewritten the torrc, so the stale 'enabled'
                ## read let set_torrc() run and immediately re-enable + restart
                ## Tor -- the exact opposite of the click. The continuation
                ## finishes the UI update when the worker returns.
                self.run_async(tor_status.set_disabled,
                               lambda result: self.exit_configuration())
                return

            elif self.bridges_combo.currentText() == 'Enable network':
                ## Terminal action, same reasoning as 'Disable network'. A proxy
                ## or bridge change is a separate configure step; a toggle does
                ## not carry one.
                self.run_async(tor_status.set_enabled,
                               lambda result: self._after_enable_network())
                return

            if self.proxy_combo.currentText() != 'None':
                if self.check_valid_proxy_settings():
                    self.use_proxy = True
                else:
                    self.invalid_proxy_box.setWindowModality(QtCore.Qt.WindowModal)
                    self.invalid_proxy_box.exec_()
                    return

            else:
                self.use_proxy = False

            tor_is_enabled = tor_status.tor_status() == 'tor_enabled'
            if not tor_is_enabled:
                self.refresh(True)
                self.restart_button.setEnabled(False)
            if not self.use_custom_bridges and tor_is_enabled :
                self.set_torrc()

    def set_torrc(self):
        args = []

        if self.use_default_bridges:
            args.append(self.bridges_combo.currentText().split()[0])
        else:
            args.append('None')

        if self.use_custom_bridges:
            args.append(self.custom_bridges.toPlainText())
        else:
            args.append('None')

        if self.use_proxy:
            args.append(self.proxy_combo.currentText())
            args.append(self.proxy_ip_edit.text())
            args.append(self.proxy_port_edit.text())
            ## Always strings from the proxy fields; append unconditionally so
            ## gen_torrc() receives the 7 arguments it needs to emit the proxy.
            args.append(self.proxy_user_edit.text())
            args.append(self.proxy_pwd_edit.text())
        else:
            args.append('None')

        torrc_gen.gen_torrc(args)
        self.restart_tor()
        self.exit_configuration()

    def exit_configuration(self):
        self.configure_button.setText(' Configure')
        self.configure_button.setIcon(self.tool_icon)
        self.prev_button.hide()
        self.restart_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.bridges_combo.hide()
        self.proxy_combo.hide()
        self.bridge_info_button.hide()
        self.proxy_info_button.hide()
        self.update_proxy_settings(self.proxy_type.text())
        self.proxy_ip_edit.setEnabled(False)
        self.proxy_port_edit.setEnabled(False)
        self.proxy_user_edit.setEnabled(False)
        self.proxy_pwd_edit.setEnabled(False)

    def refresh_status(self):
        self.tor_message_browser.setText(self.message)
        color = self.tor_status_color[self.tor_status_list.index(
            self.tor_status)]
        self.status.setStyleSheet('background-color:%s; color:white; \
                                  font:bold' % color)

    def refresh_logs(self):
        for button in self.files_box.findChildren(QRadioButton):
            if not button.isChecked():
                continue

            ## Dispatch on the button identity, not its label text, so a wording
            ## change to a radio cannot silently break log selection.
            if button is self.journal_button:
                if self.journal_command is None:
                    ## __init__ found no way to escalate, so there is no
                    ## command to run; say so instead of raising on Popen(None).
                    text = ('The systemd journal cannot be read: no privilege '
                            'escalation method (privleap, pkexec or '
                            'passwordless sudo) is available.')
                else:
                    journal_proc = Popen(self.journal_command, stdout=PIPE,
                                         stderr=PIPE)
                    stdout, stderr = journal_proc.communicate()
                    ## Journal content is untrusted; decode defensively (a
                    ## malformed byte must not crash the log view) then strip
                    ## control characters, escape sequences and markup.
                    text = sanitize_string(stdout.decode(errors='replace'))

            # Last n lines of the Tor log, HTML-formatted to highlight warnings
            # and errors.
            elif button is self.log_button:
                if os.path.exists(self.tor_log):
                    ## Last 3000 lines of the Tor log, read directly rather
                    ## than shelling out to 'tail'.
                    with open(self.tor_log, 'r', encoding='utf-8',
                              errors='replace') as tor_log_file:
                        lines = tor_log_file.read().split('\n')[-3000:]
                    html_lines = []
                    for line in lines:
                        ## Tor log lines are untrusted and are embedded into
                        ## HTML below; strip control characters, escape
                        ## sequences and markup first so they cannot inject
                        ## into the log view.
                        line = sanitize_string(line) + '\n'
                        ## Redact the fixed column range; using the slice as a
                        ## regex pattern crashes on metacharacters and, when
                        ## empty, inserts '...' between chars. Guard short lines
                        ## (e.g. blank tail output) so they are not suffixed
                        ## with a spurious '...'.
                        if len(line) > 19:
                            line = line[:12] + '...' + line[19:]
                        line = line.replace('[warn]', self.warn_style)
                        line = line.replace('[error]', self.error_style)
                        if '[warn]' in line or '[error]' in line:
                            line = line.replace('\n', '</span><br>')
                        else:
                            line = line.replace('\n', '<br>')
                        html_lines.append(line)
                    text = ''.join(html_lines)
                else:
                    text = 'Something is wrong: directory /run/tor does not exists. Try to restart Tor.'

            elif button is self.torrc_button:
                torrc_path = torrc_gen.torrc_path()
                ## On plain Debian / Kicksecure the drop-in may not exist yet;
                ## show a note instead of crashing with FileNotFoundError.
                if os.path.exists(torrc_path):
                    with open(torrc_path, encoding='utf-8') as torrc_file:
                        ## torrc may contain user-supplied content; redact proxy
                        ## credentials (this is the copy-into-a-forum-post
                        ## surface info.tor_stopped() points users at) BEFORE
                        ## sanitizing markup/control for display. cat() on the
                        ## stdout path already redacts the same content.
                        text = sanitize_string(
                            tor_status.redact_credentials(torrc_file.read()))
                else:
                    text = 'No tor-control-panel torrc exists yet.'

            self.file_browser.setText(text)
            self.file_browser.moveCursor(QtGui.QTextCursor.End)

    def refresh_user_configuration(self):
        args = torrc_gen.parse_torrc()

        self.bridge_type.setText(args[0])
        index = self.bridges_combo.findText(args[0])
        self.bridges_combo.setCurrentIndex(index)

        ## Assign both flags on every refresh so a previous default/custom
        ## selection cannot leak into a later set_torrc() and emit conflicting
        ## bridge configuration.
        bridge_type = self.bridge_type.text()
        self.use_default_bridges = bridge_type in self.default_bridges
        self.use_custom_bridges = bridge_type == 'Custom bridges'

        self.proxy_type.setText(args[1])
        if self.proxy_type.text() != 'None':
            ## proxy_type was just set to args[1], so it is not 'None' here.
            self.use_proxy = True
            index = self.proxy_combo.findText(args[1])
            self.proxy_combo.setCurrentIndex(index)
            self.proxy_ip_edit.setText(args[2])
            self.proxy_port_edit.setText(args[3])
            self.proxy_user_edit.setText(args[4])
            self.proxy_pwd_edit.setText(args[5])
        else:
            self.use_proxy = False

    def set_network_toggle(self, label):
        ## Ensure the bridges selector ends with exactly one network toggle
        ## entry ('Disable network' or 'Enable network'). Removing by text
        ## rather than a hard-coded index avoids appending duplicates.
        for text in ('Disable network', 'Enable network'):
            index = self.bridges_combo.findText(text)
            while index != -1:
                self.bridges_combo.removeItem(index)
                index = self.bridges_combo.findText(text)
        self.bridges_combo.addItem(label)

    def refresh(self, bootstrap):
        ## get status
        tor_is_enabled = tor_status.tor_status() == 'tor_enabled'
        tor_is_running = os.path.exists(self.tor_running_path)

        if tor_is_enabled and tor_is_running:
            self.tor_status = 'running'
            tor_state = True
            ## Tor is up, so the only meaningful toggle is turning it off. The
            ## Accept handler dispatches on the entry TEXT, so a stale 'Enable
            ## network' left from an earlier state would both hide the disable
            ## action and make Accept re-run set_enabled + restart_tor.
            self.set_network_toggle('Disable network')
            ## when refresh is called from update_bootstrap, the thread
            ## would be destroyed while running, crashing the program.
            if bootstrap:
                self.start_bootstrap()

        else:
            if not tor_is_running:
                self.tor_status = 'stopped'
                tor_state = False
                self.set_network_toggle('Disable network')

            if not tor_is_enabled:
                if tor_is_running:
                    self.tor_status = 'disabled-running'
                    tor_state = True
                    self.set_network_toggle('Enable network')

                elif not tor_is_running:
                    self.tor_status = 'disabled'
                    tor_state = False
                    self.set_network_toggle('Enable network')
            self.message = self.tor_message[self.tor_status_list.index(
                self.tor_status)]

        self.newnym_button.setEnabled(tor_state)

        self.refresh_status()
        self.refresh_user_configuration()
        self.refresh_logs()

    def restart_tor(self):
        if not self.bootstrap_done:
            self.stop_bootstrap_thread()
        ## if running restart tor directly stem returns
        ## bootstrap_percent 100 or a socket error, randomly.
        ## The restart has to wait for the stop to finish, so it continues in
        ## the completion slot rather than on the next line.
        self.stop_tor(on_done=self._after_stop_for_restart)

    def _after_stop_for_restart(self):
        ## GUI-thread continuation, once Tor has actually stopped.
        self.restart_button.setEnabled(False)
        argv = self.privileged_argv('acw-tor-control-restart')
        if argv is None:
            return
        ## Fire-and-forget: bootstrap tracking below reflects the restart.
        Popen(argv)
        self.start_bootstrap()

    def stop_tor(self, on_done=None):
        """Stop Tor off the GUI thread; continue in `on_done` when it is down.

        The wait() this replaces ran in the clicked slot, so the window stopped
        repainting for the whole stop -- and under pkexec for the authentication
        prompt too. It cannot simply be dropped: refresh() decides the panel's
        state from whether Tor's pid file still exists, so it has to run after
        the stop completes, not beside it.
        """
        self.restart_button.setEnabled(True)
        if not self.bootstrap_done:
            self.bootstrap_progress.hide()
            self.stop_bootstrap_thread()

        argv = self.privileged_argv('acw-tor-control-stop')
        if argv is None:
            return

        def _finished(_result):
            self.refresh(True)
            if on_done is not None:
                on_done()

        self.run_async(lambda: Popen(argv).wait(), _finished)

    def quit(self):
        if not self.bootstrap_done:
            self.stop_bootstrap_thread()
        ## Stop/restart hand their privileged work to a worker thread, so exiting
        ## right after clicking Stop could otherwise tear the window down with the
        ## operation still in flight.
        wait_for_commands(self)
        self.accept()


def signal_handler(sig, frame):
    sys.exit(128 + sig)


def main():
    if os.geteuid() == 0:
        print('tor_control_panel.py: ERROR: Do not run with sudo / as root!')
        sys.exit(1)

    app = QApplication(sys.argv)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timer = QtCore.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    tor_controller = TorControlPanel()
    tor_controller.refresh(True)
    tor_controller.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
