"""Subprocess helper used by every CLI-based scanner."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path


class ToolNotInstalled(Exception):
    pass


class ToolSkipped(Exception):
    """Raised by a scanner when it decides it has nothing to do."""


class ToolCancelled(Exception):
    """Raised when the user cancels the scan while a tool is running."""


def is_cancelled() -> bool:
    """A scan sets `cancel` on the thread running each tool (see pipeline). Scanners with their
    own Python wait-loops (ZAP, OpenVAS) call this so cancellation interrupts them too."""
    cb = getattr(threading.current_thread(), "cancel", None)
    try:
        return bool(cb and cb())
    except Exception:
        return False


def _terminate(proc: subprocess.Popen) -> None:
    """Kill the tool and all its children (it was started in its own process group)."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def which(binary: str) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    for extra in ("/opt/tools/bin", "/opt/tools/nikto/program", "/opt/tools/testssl"):
        p = Path(extra) / binary
        if p.exists():
            return str(p)
    return None


def require(binary: str) -> str:
    path = which(binary)
    if not path:
        raise ToolNotInstalled(f"'{binary}' is not installed (it is included in the Docker image)")
    return path


def run(cmd: list[str], timeout: int, cwd: Path | None = None, env: dict | None = None,
        ok_codes: tuple[int, ...] | None = (0,), poll: float = 2.0) -> subprocess.CompletedProcess:
    """Run a command without a shell, polling so it can be killed on timeout or user cancel.
    ok_codes=None accepts any exit code."""
    full_env = {**os.environ, **(env or {})}
    name = Path(cmd[0]).name
    # Output goes to temp files (not pipes) so a chatty tool can never deadlock the poll loop.
    with tempfile.TemporaryFile("w+", errors="replace") as fout, tempfile.TemporaryFile("w+", errors="replace") as ferr:
        proc = subprocess.Popen(cmd, stdout=fout, stderr=ferr, cwd=cwd, env=full_env, start_new_session=True)
        start = time.time()
        while proc.poll() is None:
            time.sleep(poll)
            if is_cancelled():
                _terminate(proc)
                raise ToolCancelled(f"{name} cancelled by user")
            if time.time() - start > timeout:
                _terminate(proc)
                raise RuntimeError(f"{name} timed out after {timeout}s")
        fout.seek(0)
        ferr.seek(0)
        out, err = fout.read(), ferr.read()
    proc_result = subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    if ok_codes is not None and proc.returncode not in ok_codes:
        tail = (err or out or "").strip()[-800:]
        raise RuntimeError(f"{name} exited with {proc.returncode}: {tail}")
    return proc_result
