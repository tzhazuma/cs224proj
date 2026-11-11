from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = "dynamic-cwe401/1.0"
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_COMPILE_TIMEOUT_S = 120.0
DEFAULT_VALGRIND_TIMEOUT_FACTOR = 3.0
DEFAULT_DETECTORS = ("asan", "valgrind")


def asan_environment(
    base: Optional[dict[str, str]],
    log_prefix: Path,
    extra_options: str = "",
) -> dict[str, str]:
    env = dict(base or os.environ)
    options = (
        "detect_leaks=1:abort_on_error=0:"
        "exitcode=23:print_summary=1:"
        f"log_path={log_prefix}"
    )
    if extra_options:
        options = f"{options}:{extra_options}"
    env["ASAN_OPTIONS"] = options
    env["LSAN_OPTIONS"] = "exitcode=23"
    env["LC_ALL"] = "C"
    return env


def valgrind_command(
    valgrind_bin: str,
    binary: Path,
    xml_path: Path,
    log_path: Path,
    argv: list[str],
    extra_args: Optional[list[str]] = None,
) -> list[str]:
    command = [
        valgrind_bin,
        "--tool=memcheck",
        "--leak-check=full",
        "--show-leak-kinds=definite,indirect,possible",
        "--errors-for-leak-kinds=definite",
        "--error-exitcode=99",
        "--xml=yes",
        f"--xml-file={xml_path}",
        f"--log-file={log_path}",
        "--num-callers=20",
        "--child-silent-after-fork=yes",
    ]
    command.extend(extra_args or [])
    command.append(str(binary))
    command.extend(argv)
    return command
