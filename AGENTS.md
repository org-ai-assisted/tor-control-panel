## Tests

Comprehensive tests for tor-control-panel (which now also contains the merged
anon-connection-wizard) -- an offscreen PyQt5 suite exercising torrc generation
and parsing for every bridge and proxy type, the wizard Cancel-crash and
bridges-selector regressions from arraybolt3's review, plus the interactive GUI
walkthrough as skipped tests -- are too high-volume for human review and live in
the AI-maintained dist-ai repo, not here:

  https://github.com/org-ai-assisted/dist-ai -> usr/share/tor-control-panel-tests/

Run them against this checkout:

    TCP_REPO="$PWD" tor-control-panel-tests
