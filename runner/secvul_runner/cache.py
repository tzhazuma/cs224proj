"""Per-request atomic JSON cache used for resume and audit."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

CACHE_SCHEMA_VERSION = 1
logger = logging.getLogger(__name__)


class CacheError(RuntimeError):
    pass


class RequestCache:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, dataset_type: str, task: str, key: str) -> Path:
        return self.root / dataset_type / task / key[:2] / f"{key}.json"

    def read(
        self,
        *,
        dataset_type: str,
        task: str,
        key: str,
        request_fingerprint: str,
    ) -> dict[str, Any] | None:
        path = self.path_for(dataset_type, task, key)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("ignoring unreadable cache entry %s: %s", path, exc)
            return None
        if not isinstance(record, dict):
            logger.warning("ignoring non-object cache entry %s", path)
            return None
        if record.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
            logger.warning("ignoring cache entry with incompatible schema: %s", path)
            return None
        if record.get("request_fingerprint") != request_fingerprint:
            logger.warning("ignoring cache entry with a different request fingerprint: %s", path)
            return None
        return record

    def write(
        self,
        *,
        dataset_type: str,
        task: str,
        key: str,
        request_fingerprint: str,
        record: dict[str, Any],
    ) -> Path:
        path = self.path_for(dataset_type, task, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_schema_version": CACHE_SCHEMA_VERSION,
            "cache_key": key,
            "request_fingerprint": request_fingerprint,
            **record,
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_name = handle.name
                handle.write(text)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        except OSError as exc:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
            raise CacheError(f"cannot write cache entry {path}: {exc}") from exc
        return path
