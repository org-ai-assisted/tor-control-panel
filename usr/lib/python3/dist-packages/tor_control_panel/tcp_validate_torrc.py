#!/usr/bin/python3 -Bsu

## Copyright (c) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Ensures that the specified torrc file contains only valid configuration like
what tor-control-panel would write.
"""

import sys
from pathlib import Path
from typing import NoReturn

from .tor_control_panel_lib import (
    TcplTorConfInfo,
    tcpl_parse_torrc,
)


def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) != 2:
        print("Wrong number of arguments!", file=sys.stderr)
        sys.exit(1)

    torrc_path: Path = Path(sys.argv[1])
    if not torrc_path.is_file():
        print(
            "Specified path '{str(torrc_path)}' is not a file!",
            file=sys.stderr,
        )
        sys.exit(1)

    parse_rslt: TcplTorConfInfo | str = tcpl_parse_torrc(torrc_path)
    if isinstance(parse_rslt, str):
        print(
            f"Could not parse torrc: '{parse_rslt}'",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
