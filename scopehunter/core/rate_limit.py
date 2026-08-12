"""
rate_limit.py — Token-bucket rate limiter for async HTTP requests.

Ensures we never exceed the configured requests-per-second.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """
    Async token-bucket rate limiter.

    Usage:
        limiter = RateLimiter(requests_per_second=5)
        async with limiter:
            response = await client.get(url)
    """

    def __init__(self, requests_per_second: float = 5.0) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive.")
        self.rps = requests_per_second
        self._min_interval = 1.0 / requests_per_second
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until it's safe to send the next request."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            wait_time = self._min_interval - elapsed
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_request_time = time.monotonic()

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        pass
