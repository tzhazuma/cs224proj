"""Append-only cost ledger (llm/ledger.jsonl) and per-run / global budget guards."""

from __future__ import annotations

import fcntl
import json
import os
import threading
from pathlib import Path
from typing import Any

from . import LLM_DIR

LEDGER_PATH = LLM_DIR / "ledger.jsonl"

# Global hard stops across all runs (README section 7). Currency per provider.
GLOBAL_CAPS = {"deepseek": ("CNY", 9.5), "jev": ("USD", 4.0)}


class Ledger:
    """One JSON object per line. Writers take an exclusive flock and fsync every append."""

    def __init__(self, path: Path = LEDGER_PATH) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def spent(self, provider: str) -> float:
        return sum(
            float(r.get("cost") or 0.0)
            for r in self.records()
            if r.get("kind") == "call" and r.get("provider") == provider
        )

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX)
                try:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    """Thread-safe reservation budget.

    A call reserves a conservative estimate before it is sent and settles to the
    usage-based cost afterwards; a call is refused when ledger spend (all earlier
    runs) + this run's spend + open reservations + estimate would pass either cap.
    """

    def __init__(self, provider: str, run_cap: float, ledger_spent: float,
                 global_cap: float | None = None) -> None:
        currency, default_cap = GLOBAL_CAPS[provider]
        self.provider = provider
        self.currency = currency
        self.global_cap = default_cap if global_cap is None else global_cap
        self.run_cap = run_cap
        self.ledger_spent = ledger_spent
        self.run_spent = 0.0
        self.reserved = 0.0
        self._lock = threading.Lock()

    def reserve(self, estimate: float) -> None:
        with self._lock:
            run_after = self.run_spent + self.reserved + estimate
            if run_after > self.run_cap:
                raise BudgetExceeded(
                    f"{self.provider}: run cap {self.run_cap} {self.currency} would be exceeded "
                    f"(spent {self.run_spent:.6f}, reserved {self.reserved:.6f}, next {estimate:.6f})")
            if self.ledger_spent + run_after > self.global_cap:
                raise BudgetExceeded(
                    f"{self.provider}: global hard stop {self.global_cap} {self.currency} would be "
                    f"exceeded (ledger {self.ledger_spent:.6f} + run {run_after:.6f})")
            self.reserved += estimate

    def settle(self, estimate: float, actual: float) -> None:
        with self._lock:
            self.reserved = max(0.0, self.reserved - estimate)
            self.run_spent += actual

    @property
    def total_spent(self) -> float:
        return self.ledger_spent + self.run_spent
