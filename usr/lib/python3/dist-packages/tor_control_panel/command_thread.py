#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Off-GUI-thread execution of blocking privileged work, shared by both
front-ends.

The privileged helpers (leaprun / pkexec / sudo) block until systemd answers,
and under pkexec that span includes the authentication prompt. Running them
directly in a clicked slot freezes the window for the whole duration, so every
front-end needs the same small amount of machinery; it lives here rather than
in tor_control_panel, which anon_connection_wizard does not import.
"""

from PyQt5 import QtCore


class CommandThread(QtCore.QThread):
    ## Runs a blocking privileged / subprocess operation (e.g. Enable network's
    ## leaprun calls) off the GUI thread so the UI stays responsive. The callable
    ## must NOT touch Qt widgets -- do any UI work in the `done` slot, which fires
    ## on the GUI thread.
    done = QtCore.pyqtSignal(object)

    def __init__(self, parent, func):
        super().__init__(parent)
        self._func = func

    def run(self):
        try:
            result = self._func()
        except Exception:
            result = None
        self.done.emit(result)


class _Continuation(QtCore.QObject):
    """Runs a run_async completion, and dies with the owner it is parented to."""

    def __init__(self, owner, on_done):
        super().__init__(owner)
        self._on_done = on_done

    def deliver(self, result):
        self._on_done(result)


def _thread_set(owner):
    """The owner's live workers, pruned of the ones that have already ended.

    A LIST, and pruned on the way in rather than from a finished handler. The
    obvious 'finished -> discard(thread)' needs to hash the QThread wrapper at a
    moment when its C++ object may already be gone, which segfaults instead of
    raising; doing the housekeeping here means it only ever touches threads that
    are known to still exist.
    """
    if not hasattr(owner, '_command_threads'):
        ## Strong references, so a running QThread is not garbage collected.
        owner._command_threads = []
    owner._command_threads = [
        running for running in owner._command_threads
        if not running.isFinished()]
    return owner._command_threads


def run_async(owner, func, on_done):
    """Run `func` off the GUI thread; `on_done(result)` runs back on it."""
    ## Deliberately NO QObject parent. The owner widget can be destroyed while
    ## a worker is still running -- click Stop, then Exit straight after -- and
    ## destroying a parent takes its children with it, which for a running
    ## QThread aborts the process. Lifetime is held by the set below instead.
    thread = CommandThread(None, func)
    _thread_set(owner).append(thread)

    ## Deliver through a QObject PARENTED to the owner, never a bare callable.
    ## The owner can be destroyed while the worker is still running, and the
    ## continuation almost always touches it (stop_tor's calls refresh()), which
    ## against a freed C++ object takes the process down with SIGSEGV rather
    ## than raising anything Python can catch. Qt drops queued signals to a
    ## destroyed receiver, so tying the receiver's lifetime to the owner is what
    ## makes that safe -- a plain closure gets no such treatment.
    continuation = _Continuation(owner, on_done)
    thread.done.connect(continuation.deliver)
    thread.start()
    return thread


def wait_for_commands(owner, timeout_ms=10000):
    """Block until the owner's outstanding run_async work has finished.

    Call this before tearing the window down. A privileged worker still running
    when the process exits leaves the operation half-applied, and the wait is
    what makes "Stop, then Exit immediately" behave.
    """
    for thread in list(getattr(owner, '_command_threads', ())):
        thread.wait(timeout_ms)


def run_keeping_ui_alive(owner, func):
    """Run `func` off the GUI thread, but do not return until it has finished.

    For a TERMINAL action -- one the window closes right after -- where the work
    must actually complete. A plain run_async() there is wrong: the dialog
    closes and the process can exit with the operation half-applied, which for
    the wizard's Cancel would leave Tor in neither the old nor the new state.

    A local event loop keeps the UI repainting instead of showing a frozen
    window. The caller is responsible for disabling whatever the user must not
    click while it spins -- a nested event loop still delivers input.
    """
    loop = QtCore.QEventLoop()
    captured = {}

    ## Parentless for the same reason as run_async().
    thread = CommandThread(None, func)
    thread.done.connect(lambda result: captured.__setitem__('result', result))
    thread.finished.connect(loop.quit)
    thread.start()
    loop.exec_()
    ## finished fires just before the thread fully stops; wait() makes the
    ## hand-back deterministic for callers that tear down straight after.
    thread.wait()
    return captured.get('result')
