"""In-memory sliding-window rate limiting and brute-force lockout.

Kept dependency-free and process-local: the API runs as a single uvicorn
process on Render's free tier, so an in-memory store is sufficient and avoids
sharing lockout state through the database. All limits are tunable through
environment variables so tests can exercise them with small values.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, value)


def global_rate_limit_per_minute() -> int:
    return _env_int("GLOBAL_RATE_LIMIT_PER_MINUTE", 600)


def auth_rate_limit_per_minute() -> int:
    return _env_int("AUTH_RATE_LIMIT_PER_MINUTE", 30)


def analyze_rate_limit_per_minute() -> int:
    return _env_int("ANALYZE_RATE_LIMIT_PER_MINUTE", 12)


def auth_max_failures() -> int:
    return _env_int("AUTH_MAX_FAILURES", 5)


def auth_failure_window_minutes() -> int:
    return _env_int("AUTH_FAILURE_WINDOW_MINUTES", 15)


def auth_lockout_minutes() -> int:
    return _env_int("AUTH_LOCKOUT_MINUTES", 15)


def get_client_ip(request) -> str:
    """Best-effort client IP. X-Forwarded-For is only trusted when the app
    runs behind a proxy (Render), signalled by TRUST_PROXY=1."""
    trust_proxy = os.getenv("TRUST_PROXY", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class SlidingWindowLimiter:
    """Thread-safe sliding-window counter keyed by an arbitrary string."""

    MAX_TRACKED_KEYS = 10_000

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Record one hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = int(window_seconds - (now - hits[0])) + 1
                return False, retry_after
            hits.append(now)
            if len(self._hits) > self.MAX_TRACKED_KEYS:
                self._prune(now, window_seconds)
            return True, 0

    def _prune(self, now: float, window_seconds: int) -> None:
        stale = [
            key
            for key, hits in self._hits.items()
            if not hits or now - hits[-1] >= window_seconds
        ]
        for key in stale:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class FailureTracker:
    """Counts authentication failures per key (normally the login email).

    Once a key accumulates ``auth_max_failures()`` failures inside the
    window, further attempts are rejected for ``auth_lockout_minutes()`` —
    even with the correct password — until the lockout expires.
    """

    MAX_TRACKED_KEYS = 10_000

    def __init__(self) -> None:
        self._failures: dict[str, list[tuple[float, float]]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        stale = [
            key
            for key, entries in self._failures.items()
            if not entries or all(now - stamp >= 3600 for stamp, _ in entries)
        ]
        for key in stale:
            self._failures.pop(key, None)

    def locked_for(self, key: str) -> float:
        """Seconds the key remains locked (0 when not locked)."""
        threshold = auth_max_failures()
        lock_seconds = auth_lockout_minutes() * 60
        window_seconds = auth_failure_window_minutes() * 60
        now = time.time()
        with self._lock:
            entries = self._failures.get(key, [])
            recent = [stamp for stamp, _ in entries if now - stamp < window_seconds]
            if len(recent) >= threshold:
                newest = max(stamp for stamp, _ in entries)
                remaining = (newest + lock_seconds) - now
                return remaining if remaining > 0 else 0.0
            return 0.0

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            entries = self._failures.setdefault(key, [])
            entries.append((now, now))
            window_seconds = auth_failure_window_minutes() * 60
            self._failures[key] = [
                (stamp, value) for stamp, value in entries if now - stamp < window_seconds
            ]
            if len(self._failures) > self.MAX_TRACKED_KEYS:
                self._prune(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


limiter = SlidingWindowLimiter()
login_failures = FailureTracker()
