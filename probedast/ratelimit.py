"""Per-host token bucket rate limiting with adaptive backoff on 429/5xx.

MemoryRateLimiter is correct for a single process. RedisRateLimiter uses the
same bucket shared across worker processes, updated atomically with a Lua
script so a read-modify-write race between two workers can't double-spend
tokens (same reasoning as the SETNX session lock in auth.py).
"""
from __future__ import annotations
import asyncio
import time

TOKEN_BUCKET_LUA = """
local d = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local rate = tonumber(ARGV[1]); local burst = tonumber(ARGV[2])
local t = redis.call('TIME'); local now = t[1] * 1000 + math.floor(t[2] / 1000)
local tokens = tonumber(d[1]); local ts = tonumber(d[2])
if tokens == nil then tokens = burst; ts = now end
tokens = math.min(burst, tokens + (now - ts) / 1000 * rate)
local wait = 0
if tokens < 1 then wait = math.ceil((1 - tokens) / rate * 1000) end
tokens = tokens - 1
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], 60)
return wait
"""


class _Backoff:
    """Exponential slowdown per host on 429 / repeated 5xx; recovers gradually."""
    def __init__(self):
        self.mult: dict = {}

    def penalize(self, host: str):
        self.mult[host] = min(self.mult.get(host, 1.0) * 2, 32.0)

    def reward(self, host: str):
        m = self.mult.get(host, 1.0)
        if m > 1.0:
            self.mult[host] = max(1.0, m * 0.9)

    def factor(self, host: str) -> float:
        return self.mult.get(host, 1.0)


class MemoryRateLimiter(_Backoff):
    def __init__(self, rps: float = 10.0, burst: int | None = None):
        super().__init__()
        self.rps = rps
        self.burst = burst or max(1, int(rps))
        self._state: dict = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        rate = self.rps / self.factor(host)
        async with self._lock:
            now = time.monotonic()
            tokens, ts = self._state.get(host, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - ts) * rate)
            wait = 0.0 if tokens >= 1 else (1 - tokens) / rate
            self._state[host] = (tokens - 1, now)
        if wait:
            await asyncio.sleep(wait)


class RedisRateLimiter(_Backoff):
    def __init__(self, redis, rps: float = 10.0, burst: int | None = None):
        super().__init__()
        self.r, self.rps, self.burst = redis, rps, burst or max(1, int(rps))
        self._script = redis.register_script(TOKEN_BUCKET_LUA)

    async def acquire(self, host: str) -> None:
        rate = self.rps / self.factor(host)
        wait_ms = await self._script(keys=[f"ratelimit:{host}"], args=[rate, self.burst])
        if wait_ms:
            await asyncio.sleep(int(wait_ms) / 1000)
