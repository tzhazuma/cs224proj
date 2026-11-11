"""Small standard-library helpers shared by the repair evaluation tool."""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class RepairEvalError(ValueError):
    """Raised for malformed inputs or unsafe output requests."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def salted_id(salt: str, *parts: Any) -> str:
    message = canonical_json(list(parts)).encode("utf-8")
    return hmac.new(salt.encode("utf-8"), message, hashlib.sha256).hexdigest()


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except OSError as exc:
        raise RepairEvalError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RepairEvalError(f"invalid JSON in {path}: {exc}") from exc


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise RepairEvalError(
                        f"invalid JSON in {path} at line {line_number}: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise RepairEvalError(
                        f"{path} line {line_number}: record must be a JSON object"
                    )
                rows.append(value)
    except OSError as exc:
        raise RepairEvalError(f"cannot read {path}: {exc}") from exc
    if not rows:
        raise RepairEvalError(f"{path} contains no records")
    return rows


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _atomic_write(path, text.encode("utf-8"))


def write_text(path: Path, text: str) -> None:
    _atomic_write(path, text.encode("utf-8"))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    text = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )
    _atomic_write(path, text.encode("utf-8"))


def write_tsv(path: Path, header: list[str], rows: Iterable[list[Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
            writer.writerow(header)
            for row in rows:
                writer.writerow(["" if value is None else value for value in row])
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_tsv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if reader.fieldnames is None:
                raise RepairEvalError(f"{path} has no TSV header")
            header = [field.strip() for field in reader.fieldnames]
            rows: list[dict[str, str]] = []
            for line_number, row in enumerate(reader, start=2):
                clean: dict[str, str] = {}
                for key, value in row.items():
                    if key is None:
                        continue
                    clean[key.strip()] = "" if value is None else value.strip()
                if not any(clean.values()):
                    continue
                clean["_line"] = str(line_number)
                rows.append(clean)
    except OSError as exc:
        raise RepairEvalError(f"cannot read {path}: {exc}") from exc
    return header, rows


def prepare_output_dir(path: Path, *, allow_existing_empty: bool = True) -> None:
    if path.exists():
        if not path.is_dir():
            raise RepairEvalError(f"output path exists and is not a directory: {path}")
        entries = list(path.iterdir())
        if entries or not allow_existing_empty:
            raise RepairEvalError(
                f"output directory is not empty: {path}; choose a new directory"
            )
    else:
        path.mkdir(parents=True, exist_ok=True)


def relative_to(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)
