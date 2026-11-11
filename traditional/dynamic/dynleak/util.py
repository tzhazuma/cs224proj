from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slugify(text: str, max_len: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    if not cleaned:
        cleaned = "case"
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip("._-")
    return cleaned


def short_hash(text: str, length: int = 8) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:length]


def truncate_text(text: str, limit: int = 12000, marker: str = "\n...[truncated]") -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(marker))] + marker


def decode_bytes(data: Optional[bytes]) -> str:
    if not data:
        return ""
    return data.decode("utf-8", "replace")


def read_text(path: Path, limit: Optional[int] = None) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            if limit is None:
                return handle.read()
            return handle.read(limit)
    except OSError:
        return ""


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(tmp, path)


def dumps_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def which(name: str) -> Optional[str]:
    from shutil import which as _which

    return _which(name)


def tool_version(command: str, timeout_s: float = 10.0) -> str:
    try:
        proc = subprocess.run(
            [command, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
            check=False,
        )
        first = decode_bytes(proc.stdout).strip().splitlines()
        if first:
            return first[0].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc = subprocess.run(
            [command, "-dumpfullversion"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
            check=False,
        )
        text = decode_bytes(proc.stdout).strip()
        if text:
            return text.splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


@dataclass
class ProcResult:
    command: list[str]
    exit_code: Optional[int]
    signal_number: Optional[int]
    timed_out: bool
    duration_ms: int
    stdout: str
    stderr: str
    stdout_path: Optional[str]
    stderr_path: Optional[str]
    spawn_error: Optional[str] = None

    @property
    def signal_name(self) -> Optional[str]:
        if not self.signal_number:
            return None
        try:
            return signal.Signals(self.signal_number).name
        except ValueError:
            return f"SIG{self.signal_number}"


def _read_limited(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit)
        return decode_bytes(data)
    except OSError:
        return ""


def run_process(
    command: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
    timeout_s: float = 10.0,
    stdin_data: Optional[bytes | str] = None,
    stdout_path: Optional[Path] = None,
    stderr_path: Optional[Path] = None,
    capture_limit: int = 65536,
) -> ProcResult:
    """Run *command* as its own process group and enforce a wall-clock timeout.

    Output is streamed to files when paths are given, so huge program output
    cannot exhaust the parent's memory.  A short preview is read back for the
    JSONL record.
    """
    if stdout_path is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
    if stderr_path is not None:
        stderr_path.parent.mkdir(parents=True, exist_ok=True)

    stdout_handle: Optional[IO[bytes]] = None
    stderr_handle: Optional[IO[bytes]] = None
    stdout_target: Any = subprocess.PIPE
    stderr_target: Any = subprocess.PIPE
    if stdout_path is not None:
        stdout_handle = stdout_path.open("wb")
        stdout_target = stdout_handle
    if stderr_path is not None:
        stderr_handle = stderr_path.open("wb")
        stderr_target = stderr_handle

    if isinstance(stdin_data, str):
        stdin_bytes: Optional[bytes] = stdin_data.encode("utf-8")
    else:
        stdin_bytes = stdin_data

    started = time.monotonic()
    timed_out = False
    spawn_error: Optional[str] = None
    exit_code: Optional[int] = None
    stdout_data = b""
    stderr_data = b""
    process: Optional[subprocess.Popen[bytes]] = None

    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=stderr_target,
            start_new_session=True,
            close_fds=True,
        )
        try:
            out, err = process.communicate(input=stdin_bytes, timeout=timeout_s)
            stdout_data = out or b""
            stderr_data = err or b""
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                out, err = process.communicate(timeout=10)
                stdout_data = out or b""
                stderr_data = err or b""
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                out, err = process.communicate()
                stdout_data = out or b""
                stderr_data = err or b""
            exit_code = process.returncode
    except FileNotFoundError as exc:
        spawn_error = f"FileNotFoundError: {exc}"
    except OSError as exc:
        spawn_error = f"{type(exc).__name__}: {exc}"
    finally:
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()

    duration_ms = int((time.monotonic() - started) * 1000)
    signal_number: Optional[int] = None
    if exit_code is not None and exit_code < 0:
        signal_number = -exit_code

    stdout_text = decode_bytes(stdout_data)
    stderr_text = decode_bytes(stderr_data)
    if stdout_path is not None:
        stdout_text = _read_limited(stdout_path, capture_limit)
    if stderr_path is not None:
        stderr_text = _read_limited(stderr_path, capture_limit)

    return ProcResult(
        command=list(command),
        exit_code=exit_code,
        signal_number=signal_number,
        timed_out=timed_out,
        duration_ms=duration_ms,
        stdout=stdout_text,
        stderr=stderr_text,
        stdout_path=str(stdout_path) if stdout_path is not None else None,
        stderr_path=str(stderr_path) if stderr_path is not None else None,
        spawn_error=spawn_error,
    )


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
