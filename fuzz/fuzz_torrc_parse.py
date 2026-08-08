#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for tor-control-panel's torrc parsers.

The torrc round-trips through disk: user-pasted bridge lines, and content that
could be tampered with, are parsed back and (for the custom-bridge reader) fed
into a rich-text widget. These parsers must never crash and must strip control
characters. Targets:
  * torrc_gen.main_torrc_includes_dropin  -- '%include' detection
  * torrc_gen.parse_torrc                 -- read the drop-in from disk
  * torrc_gen.read_custom_bridge_lines    -- extract + sanitize custom bridges
"""

import atheris
import sys
import tempfile
from pathlib import Path

with atheris.instrument_imports():
    from tor_control_panel import torrc_gen

## Redirect the drop-in path to a scratch file so parse_torrc reads the fuzz
## input rather than the system torrc.
_SCRATCH = Path(tempfile.mkdtemp()) / '40_tor_control_panel.conf'
torrc_gen.torrc_file_path = str(_SCRATCH)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 18)

    ## Pure text parser: '%include' detection on an untrusted main torrc.
    if not isinstance(torrc_gen.main_torrc_includes_dropin(text), bool):
        raise RuntimeError('main_torrc_includes_dropin returned non-bool')

    _SCRATCH.write_text(text, encoding='utf-8')

    parsed = torrc_gen.parse_torrc()
    if not isinstance(parsed, (dict, tuple, list)):
        raise RuntimeError(f"parse_torrc returned {parsed!r}")

    lines = torrc_gen.read_custom_bridge_lines(str(_SCRATCH))
    if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
        raise RuntimeError(f"read_custom_bridge_lines returned {lines!r}")
    for item in lines:
        ## Output is inserted into a rich-text QTextEdit; it must be sanitized
        ## of raw control characters (tab excepted).
        if any(ord(char) < 32 and char not in '\t\n' for char in item):
            raise RuntimeError(f"unsanitized control char in {item!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
