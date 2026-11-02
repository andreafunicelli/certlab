"""Fixed-window rate limiter: Redis-backed with in-memory fallback."""
from __future__ import annotations

import threading
import time
from functools import lru_cache

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


class RateLimiter:
    def __init__(self, redis_url: str | None, use_redis: bool):
        self._mem: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()
        self._redis = None
        if use_redis and redis_url:
            try:
                import redis

                self._redis = redis.Redis.from_url(
                    redis_url, socket_connect_timeout=0.5, socket_timeout=0.5, decode_responses=True
                )
            except Exception:  # noqa: BLE001  # pragma: no cover - defensive
                self._redis = None

    def hit(self, key: str, limit: int, window_s: int = 60) -> tuple[bool, int]:
        """Register one hit. Returns (allowed, retry_after_seconds)."""
        if self._redis is not None:
            try:
                rkey = f"cdp:rl:{key}:{int(time.time() // window_s)}"
                pipe = self._redis.pipeline()
                pipe.incr(rkey)
                pipe.expire(rkey, window_s + 1)
                count = int(pipe.execute()[0])
                return count <= limit, window_s - int(time.time() % window_s)
            except Exception as exc:  # noqa: BLE001 - fail open to in-memory limiter
                log.warning("rate_limit_redis_unavailable", error=type(exc).__name__)
        return self._hit_memory(key, limit, window_s)

    def _hit_memory(self, key: str, limit: int, window_s: int) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            count, reset = self._mem.get(key, (0, now + window_s))
            if now >= reset:
                count, reset = 0, now + window_s
            count += 1
            self._mem[key] = (count, reset)
            if len(self._mem) > 50_000:
                self._mem = {k: v for k, v in self._mem.items() if v[1] > now}
            return count <= limit, max(1, int(reset - now))

    def reset(self) -> None:
        with self._lock:
            self._mem.clear()


@lru_cache
def get_rate_limiter() -> RateLimiter:
    s = get_settings()
    return RateLimiter(s.redis_url, s.rate_limit_backend == "redis")
