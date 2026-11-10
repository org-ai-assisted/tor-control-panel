#!/usr/bin/python3 -Bsu

## Copyright (c) 2018 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
A Qt object that monitors Tor's status. This is not included in
tor_control_panel_lib.py because it imports Qt libraries and would needlessly
inflate memory usage of applications that don't use Qt.
"""

import time

from PyQt6.QtCore import (
    QObject,
    QFileSystemWatcher,
    pyqtSignal,
)

from stem.control import Controller, EventType  # type: ignore
from stem.response.events import StatusEvent  # type: ignore

from .tor_control_panel_lib import (
    tcpl_tor_run_path_str,
    tcpl_tor_run_path,
    tcpl_tor_pid_path,
    tcpl_tor_control_path,
    tcpl_tor_auth_path,
)


class TcplTorMonitor(QObject):
    """
    Watches for changes to Tor's status and reports on them as they arrive.

    torActiveChanged's argument is a boolean representing whether Tor is now
    running or stopped.

    torBootstrapChanged's arguments are:
      * An integer specifying bootstrap progress percentage.
      * A string containing the bootstrap stage tag.
      * A string containing the bootstrap stage summary.
    """

    torActiveChanged = pyqtSignal(bool)
    torBootstrapChanged = pyqtSignal(int, str, str)
    torControllerConnectFailed = pyqtSignal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)

        self.file_watcher: QFileSystemWatcher | None = None
        self.tor_is_running: bool | None = None
        self.tor_controller: Controller | None = None

    def start_watch(self) -> None:
        """
        Starts watching Tor's status.
        """

        for attempt_idx in range(11):
            if tcpl_tor_run_path.is_dir():
                break
            if attempt_idx == 10:  ## eleventh attempt, ~10 seconds waited
                raise FileNotFoundError("/run/tor does not exist.")
            time.sleep(0.2)

        self.file_watcher = QFileSystemWatcher([tcpl_tor_run_path_str])
        self.file_watcher.directoryChanged.connect(self.tor_run_changed)

        self.tor_run_changed(tcpl_tor_run_path_str)

    def tor_run_changed(self, path: str) -> None:
        """
        Callback for when the contents of Tor's runtime dir changes.
        """

        if path != tcpl_tor_run_path_str:
            return

        if not tcpl_tor_run_path.is_dir():
            raise FileNotFoundError("/run/tor was destroyed unexpectedly!")

        if not tcpl_tor_pid_path.is_file():
            if self.tor_is_running is not False:
                self.tor_is_running = False
                self.torActiveChanged.emit(False)
            if self.tor_controller is not None:
                self.tor_controller.close()
                self.tor_controller = None
            return

        if self.tor_is_running is not True:
            self.tor_is_running = True
            self.torActiveChanged.emit(True)

        if (
            tcpl_tor_control_path.is_socket()
            and tcpl_tor_auth_path.is_file()
            and (
                self.tor_controller is None
                or not self.tor_controller.is_alive()
            )
        ):
            self.try_connect_to_tor()

    def try_connect_to_tor(self) -> None:
        """
        Attempts to set up a Tor controller connection. Retries a few times to
        work around the control socket not being immediately accessible.
        """

        tor_controller_connected: bool = False

        for _ in range(3):
            try:
                self.tor_controller = Controller.from_socket_file(
                    str(tcpl_tor_control_path)
                )
                self.tor_controller.authenticate(str(tcpl_tor_auth_path))

                current_bootstrap_str: str = self.tor_controller.get_info(
                    "status/bootstrap-phase"
                )
                current_bootstrap_list: list[str] = current_bootstrap_str.split(
                    " "
                )
                for _ in range(1):
                    if current_bootstrap_list[0] != "NOTICE":
                        break
                    if current_bootstrap_list[1] != "BOOTSTRAP":
                        break
                    current_bootstrap_list = current_bootstrap_list[2:]
                    current_bootstrap_dict: dict[str, str] = {}
                    arg_parse_success: bool = True
                    for bootstrap_item in current_bootstrap_list:
                        bootstrap_bit_list: list[str] = bootstrap_item.split(
                            "="
                        )
                        if len(bootstrap_bit_list) != 2:
                            arg_parse_success = False
                            break
                        current_bootstrap_dict[bootstrap_bit_list[0]] = (
                            bootstrap_bit_list[1]
                        )
                    if not arg_parse_success:
                        break
                    self.emit_bootstrap_event_maybe(current_bootstrap_dict)

                ## stem somehow dynamically creates EventType.STATUS_CLIENT from a
                ## string.
                # pylint: disable=no-member
                self.tor_controller.add_event_listener(
                    self.tor_bootstrap_event_handler, EventType.STATUS_CLIENT
                )

                tor_controller_connected = True
                break
            except Exception:
                if self.tor_controller is not None:
                    self.tor_controller.close()
                    self.tor_controller = None
                time.sleep(0.2)

        if not tor_controller_connected:
            self.torControllerConnectFailed.emit()

    def tor_bootstrap_event_handler(self, bootstrap_event: StatusEvent) -> None:
        """
        Handles bootstrap events from Tor.
        """

        ## Only care about bootstrap events
        if bootstrap_event.action != "BOOTSTRAP":
            return

        bootstrap_args: dict[str, str] = bootstrap_event.arguments
        self.emit_bootstrap_event_maybe(bootstrap_args)

    def emit_bootstrap_event_maybe(
        self, bootstrap_args: dict[str, str]
    ) -> None:
        """
        Checks if bootstrap_args contains the data needed to emit a bootstrap
        event, and emits it if so.
        """

        ## Make sure the event has all the info we need
        if (
            not "PROGRESS" in bootstrap_args
            or not "TAG" in bootstrap_args
            or not "SUMMARY" in bootstrap_args
        ):
            return

        progress_str: str = bootstrap_args["PROGRESS"]
        tag_str: str = bootstrap_args["TAG"]
        summary_str: str = bootstrap_args["SUMMARY"]

        ## Make sure the strings aren't unreasonably long
        if (
            len(progress_str) > 3
            or len(tag_str) > 100
            or len(summary_str) > 2048
        ):
            return

        ## Make sure the progress is numeric
        try:
            progress_int = int(progress_str)
        except Exception:
            return

        ## Make sure the progress is within range
        if not 0 <= progress_int <= 100:
            return

        self.torBootstrapChanged.emit(progress_int, tag_str, summary_str)
