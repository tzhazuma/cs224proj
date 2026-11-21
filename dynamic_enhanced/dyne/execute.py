"""Run a compiled unit under a fixed ASan/LSan environment.

stdout is read through a pty.  A leaking process is terminated by LSan and
stdio buffers would otherwise be lost on a pipe; the pty keeps the program's
observable output available for the behaviour cross-check.
"""

from __future__ import annotations

import errno
import hashlib
import os
import pty
import select
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import config


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
    env: dict[str, str]
    stdout_path: str
    stderr_path: str

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
            "env": {
                key: value
                for key, value in self.env.items()
                if key in {"ASAN_OPTIONS", "LSAN_OPTIONS", "DYNENH_REALLOC_FAIL_NONNULL"}
            },
        }


def mode_env(mode: str) -> dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = config.ASAN_OPTIONS
    if mode == "default":
        env["LSAN_OPTIONS"] = config.LSAN_OPTIONS_BASE
        env.pop("DYNENH_REALLOC_FAIL_NONNULL", None)
    elif mode == "nogobal":
        env["LSAN_OPTIONS"] = config.LSAN_OPTIONS_NOGLOBAL
        env.pop("DYNENH_REALLOC_FAIL_NONNULL", None)
    elif mode == "realloc_fail":
        env["LSAN_OPTIONS"] = config.LSAN_OPTIONS_BASE
        env["DYNENH_REALLOC_FAIL_NONNULL"] = "1"
    else:
        raise ValueError(f"unknown mode {mode}")
    return env


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
    master, slave = pty.openpty()
    started = time.monotonic()
    timed_out = False
    chunks: list[bytes] = []
    with stderr_path.open("wb") as err_stream:
        proc = subprocess.Popen(
            [str(exe)],
            stdout=slave,
            stderr=err_stream,
            env=env,
            close_fds=True,
            cwd=str(out_dir),
        )
        os.close(slave)
        deadline = started + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                proc.kill()
                break
            try:
                ready, _, _ = select.select([master], [], [], min(remaining, 0.5))
            except OSError:
                break
            if not ready:
                if proc.poll() is not None:
                    try:
                        while True:
                            data = os.read(master, 65536)
                            if not data:
                                break
                            chunks.append(data)
                    except OSError:
                        pass
                    break
                continue
            try:
                data = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            chunks.append(data)
        try:
            os.close(master)
        except OSError:
            pass
        try:
            returncode = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            returncode = proc.wait(timeout=5)
            timed_out = True
    wall_ms = int((time.monotonic() - started) * 1000)
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    stdout = b"".join(chunks).decode("utf-8", errors="replace")
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    return RunResult(
        mode=mode,
        returncode=returncode,
        timed_out=timed_out,
        wall_ms=wall_ms,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        env={key: env.get(key, "") for key in ("ASAN_OPTIONS", "LSAN_OPTIONS", "DYNENH_REALLOC_FAIL_NONNULL")},
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
