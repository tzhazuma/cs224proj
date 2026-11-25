"""Run one coverage-instrumented binary under the archived ASan/LSan policy.

stdout/stderr go to files instead of pipes.  A pipe can deadlock when the
child is killed by LSan while a reader is not draining it; the files are also
the audit trail.  The environment is reused from ``dyne.execute.mode_env`` so
the coverage run cannot silently drift from the archived one.
"""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from . import units as _units  # noqa: F401  (inserts the dyne package root)

from dyne.execute import mode_env  # noqa: E402


@dataclass
class RunResult:
    mode: str
    returncode: int | None
    timed_out: bool
    wall_ms: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_path: str
    stderr_path: str
    env: dict[str, str]

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "wall_ms": self.wall_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "env": self.env,
        }


def run_binary(
    exe: Path,
    mode: str,
    out_dir: Path,
    timeout: int = config.RUN_TIMEOUT,
) -> RunResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / "stdout.txt"
    stderr_path = out_dir / "stderr.txt"
    env = mode_env(mode)
    started = time.monotonic()
    timed_out = False
    with stdout_path.open("wb") as out_stream, stderr_path.open("wb") as err_stream:
        proc = subprocess.Popen(
            [str(exe)],
            stdout=out_stream,
            stderr=err_stream,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=str(out_dir),
            start_new_session=True,
        )
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            returncode = proc.wait(timeout=10)
    wall_ms = int((time.monotonic() - started) * 1000)
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    return RunResult(
        mode=mode,
        returncode=returncode,
        timed_out=timed_out,
        wall_ms=wall_ms,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        env={
            key: env.get(key, "")
            for key in ("ASAN_OPTIONS", "LSAN_OPTIONS", "DYNENH_REALLOC_FAIL_NONNULL")
        },
    )
