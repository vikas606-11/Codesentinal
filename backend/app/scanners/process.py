import os
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass


def run_command(cmd: list[str], cwd=None, env=None, timeout: float | None = None) -> CommandResult:
    """Like subprocess.run, but a timeout kills the whole process group.

    subprocess.run only kills the direct child; a child process of the scanner can keep the
    output pipes open and make the call hang long after the timeout.
    """
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise
    return CommandResult(proc.returncode, out, err)
