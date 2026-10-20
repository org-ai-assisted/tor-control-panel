Comprehensive tests for tor-control-panel live in the AI-maintained dist-ai repo,
not here:

  https://github.com/org-ai-assisted/dist-ai -> usr/share/tor-control-panel-tests/

Run them against this checkout (sanitize_string from helper-scripts, stem from
python3-stem, PyQt6 for the offscreen GUI):

    TCP_REPO="$PWD" QT_QPA_PLATFORM=offscreen tor-control-panel-tests

## Settled design decisions (do not re-report)

- The debug `print(self.tor_conf_info)` in tor_control_panel.py is intentional
  while the project is in active development. tor-control-panel does not log to
  the journal, so it is not a credential leak; it is commented out, not removed,
  once no longer needed.
- tcp-write-torrc does not re-check the comm FIFO in-script. The mitigation is the
  root-owned 0755 /run/tor-control-panel directory; an in-script re-check does not
  prevent a TOCTOU and adds little value.
- usr/bin/anon-connection-wizard and usr/bin/restart-tor-gui, and their .desktop
  entries, are work in progress, not orphaned: their modules are not implemented
  yet.
