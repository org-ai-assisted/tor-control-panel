#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the Tor 'status/bootstrap-phase' parser.

parse_bootstrap_phase() consumes untrusted Tor control output (it arrives over
the control socket from the Tor process and can be malformed). It must return
None or (str phase, int percent) and never crash the bootstrap thread on a
malformed line.
"""

import atheris
import sys

with atheris.instrument_imports():
    from tor_control_panel.tor_bootstrap_parse import parse_bootstrap_phase

_TAG_PHASE = {
    'starting': 'Starting',
    'conn_done': 'Connected to a relay',
    'done': 'Connected to the Tor network!',
}


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    line = fdp.ConsumeUnicodeNoSurrogates(2 ** 16)
    result = parse_bootstrap_phase(line, _TAG_PHASE)
    if result is not None:
        phase, percent = result
        if not isinstance(phase, str) or not isinstance(percent, int):
            raise RuntimeError(
                f"parse_bootstrap_phase returned {result!r} for {line!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
