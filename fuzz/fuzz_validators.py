#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for tor-control-panel's shared input validators.

valid_ip / valid_port / valid_custom_bridges classify untrusted proxy and
bridge input typed into the GUI. They must always return a bool and never raise
-- a crash here is a GUI that dies on a hostile/typo'd address. Coverage-guided
fuzzing already caught valid_ip crashing with UnicodeError (IDNA "label too
long") on an over-long host.
"""

import atheris
import sys

with atheris.instrument_imports():
    from tor_control_panel import validators


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    value = fdp.ConsumeUnicodeNoSurrogates(2 ** 16)
    for func in (validators.valid_ip, validators.valid_port,
                 validators.valid_custom_bridges):
        result = func(value)
        if not isinstance(result, bool):
            raise RuntimeError(
                f"{func.__name__} returned non-bool {result!r} for {value!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
