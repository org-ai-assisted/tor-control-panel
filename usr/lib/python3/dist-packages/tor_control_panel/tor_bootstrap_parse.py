#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Pure parsing of Tor's 'status/bootstrap-phase' control output.

Split out of the GUI bootstrap thread (tor_bootstrap.py) so it carries no PyQt
dependency and can be unit-tested and fuzzed on its own. The control output is
UNTRUSTED (it comes from the Tor process over the control socket and could be
malformed), so the parser must never crash -- it returns None on an
unrecognized line and the caller skips it.
"""

import re

from sanitize_string.sanitize_string_lib import sanitize_string


def parse_bootstrap_phase(status_line, tag_phase):
    """Parse one 'status/bootstrap-phase' line into (phase_text, percent).

    `status_line` is untrusted Tor control output; `tag_phase` maps a bootstrap
    TAG to a human-readable phase. Returns None when the line lacks a PROGRESS
    and TAG (so the caller records + skips it instead of crashing on a None
    .group()). The SUMMARY fallback is sanitized, since it is untrusted and is
    shown in the GUI.
    """
    ## Non-greedy, and clamped. Greedy '.*' took the LAST match in the line, so
    ## text inside SUMMARY="..." -- which is attacker-influenced content Tor
    ## echoes back -- could supply PROGRESS, or make TAG swallow everything up
    ## to a 'SUMMARY' appearing inside the summary text. An unclamped percent
    ## was worse: PROGRESS=999 ends tor_bootstrap's 'while percent < 100' loop
    ## without ever reaching the ==100 completion branch, so the thread exits
    ## and the wizard sits at 'Bootstrapping...' forever.
    progress_match = re.match('.*? PROGRESS=([0-9]+)', status_line)
    tag_match = re.search(r'TAG=(.*?) +SUMMARY', status_line)
    if not (progress_match and tag_match):
        return None
    percent = max(0, min(100, int(progress_match.group(1))))
    tag = tag_match.group(1)
    if tag in tag_phase:
        phase = tag_phase[tag]
    else:
        ## Unknown / newer tag: fall back to Tor's own human-readable SUMMARY
        ## (sanitized) rather than a generic placeholder.
        summary_match = re.search(r'SUMMARY="([^"]*)"', status_line)
        if summary_match:
            phase = sanitize_string(summary_match.group(1))
        else:
            phase = 'Connecting to the Tor network...'
    return phase, percent
