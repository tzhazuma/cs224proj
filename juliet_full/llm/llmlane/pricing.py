"""Prices, Beijing peak-hour rules and the off-peak gate (all clocks injectable for tests)."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo

SHANGHAI = ZoneInfo("Asia/Shanghai")

# deepseek-flash, CNY per 1M tokens, off-peak. Peak (Beijing Mon-Fri 09-12, 14-18) doubles.
DEEPSEEK_OFFPEAK_CNY_PER_M = {"input_cache_miss": 1.0, "input_cache_hit": 0.02, "output": 4.0}
DEEPSEEK_PEAK_MULTIPLIER = 2.0
DEEPSEEK_PEAK_WINDOWS = ((9, 12), (14, 18))  # Beijing local hours [start, end)

# Jev (TypeSafe), USD per 1M input tokens; output is free.
JEV_USD_PER_M_INPUT = 0.042


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_deepseek_peak(moment: datetime) -> bool:
    """True when ``moment`` (timezone-aware) falls in Beijing weekday peak hours."""
    if moment.tzinfo is None:
        raise ValueError("moment must be timezone-aware")
    local = moment.astimezone(SHANGHAI)
    if local.weekday() >= 5:
        return False
    return any(start <= local.hour < end for start, end in DEEPSEEK_PEAK_WINDOWS)


def next_offpeak(moment: datetime) -> datetime:
    """First instant at or after ``moment`` that is off-peak (minute resolution)."""
    probe = moment
    while is_deepseek_peak(probe):
        local = probe.astimezone(SHANGHAI)
        end_hour = next(end for start, end in DEEPSEEK_PEAK_WINDOWS if start <= local.hour < end)
        probe = local.replace(hour=end_hour, minute=0, second=0, microsecond=0).astimezone(moment.tzinfo)
    return probe


def deepseek_cost_cny(usage: dict[str, Any] | None, peak: bool) -> float:
    """Cost of one call from its usage block. Missing hit/miss split counts all input as miss."""
    if not usage:
        return 0.0
    prompt = int(usage.get("prompt_tokens") or 0)
    hit = usage.get("prompt_cache_hit_tokens")
    miss = usage.get("prompt_cache_miss_tokens")
    if hit is None or miss is None:
        hit, miss = 0, prompt
    out = int(usage.get("completion_tokens") or 0)
    p = DEEPSEEK_OFFPEAK_CNY_PER_M
    cost = (int(hit) * p["input_cache_hit"] + int(miss) * p["input_cache_miss"] + out * p["output"]) / 1e6
    return cost * (DEEPSEEK_PEAK_MULTIPLIER if peak else 1.0)


def deepseek_estimate_cny(prompt_chars: int, max_tokens: int) -> float:
    """Conservative pre-call reservation: ~3 chars/token, all cache-miss, max output, peak price."""
    tokens_in = prompt_chars / 3.0 + 16
    p = DEEPSEEK_OFFPEAK_CNY_PER_M
    return (tokens_in * p["input_cache_miss"] + max_tokens * p["output"]) / 1e6 * DEEPSEEK_PEAK_MULTIPLIER


def jev_cost_usd(usage: dict[str, Any] | None) -> float:
    if not usage:
        return 0.0
    return int(usage.get("input_tokens") or 0) * JEV_USD_PER_M_INPUT / 1e6


def jev_estimate_usd(state_chars: int) -> float:
    return (state_chars / 3.0 + 200) * JEV_USD_PER_M_INPUT / 1e6


class PeakHours(RuntimeError):
    pass


class PeakGate:
    """Refuses to start in peak hours; blocks workers while a peak window is open."""

    def __init__(
        self,
        now: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 30.0,
        log: Callable[[str], None] = print,
    ) -> None:
        self._now = now
        self._sleep = sleep
        self._poll = poll_seconds
        self._log = log
        self._lock = threading.Lock()
        self.paused_seconds = 0.0
        self.pause_events: list[dict[str, str]] = []

    def check_start(self) -> None:
        moment = self._now()
        if is_deepseek_peak(moment):
            local = moment.astimezone(SHANGHAI)
            raise PeakHours(
                f"DeepSeek peak hours in Beijing ({local:%a %H:%M}); next off-peak at "
                f"{next_offpeak(moment).astimezone(SHANGHAI):%a %H:%M} Beijing"
            )

    def wait_offpeak(self, stop: threading.Event | None = None) -> float:
        """Return seconds spent waiting (0 when already off-peak)."""
        waited = 0.0
        moment = self._now()
        if not is_deepseek_peak(moment):
            return 0.0
        with self._lock:
            self.pause_events.append({"paused_at_utc": moment.isoformat()})
        self._log(f"[peak-gate] peak hours started; pausing until "
                  f"{next_offpeak(moment).astimezone(SHANGHAI):%H:%M} Beijing")
        while is_deepseek_peak(self._now()):
            if stop is not None and stop.is_set():
                break
            remaining = (next_offpeak(self._now()) - self._now()).total_seconds()
            step = max(1.0, min(self._poll, remaining))
            self._sleep(step)
            waited += step
        with self._lock:
            self.paused_seconds += waited
        return waited

