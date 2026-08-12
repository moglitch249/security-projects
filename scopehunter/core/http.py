"""
http.py — Async HTTP client wrapper.

Pipeline for every request:
    1. ScopeManager.check()     ← Scope enforcement (first gate)
    2. RateLimiter.acquire()    ← Rate limiting
    3. httpx request            ← Actual HTTP request
    4. Return HttpEvidence      ← Evidence snapshot

Features:
- Automatic retries with exponential backoff (via tenacity)
- Configurable timeouts
- Session profile support (User A / User B / Admin)
- Read-only by default (GET, HEAD, OPTIONS only in safe mode)
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from scopehunter.core.evidence import HttpEvidence, SessionProfile
from scopehunter.core.rate_limit import RateLimiter
from scopehunter.core.scope import ScopeManager, ScopeViolation

logger = logging.getLogger(__name__)

# Maximum snippet length stored from response bodies
_BODY_SNIPPET_LIMIT = 512

# Safe HTTP methods allowed in normal scanning
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})

DEFAULT_HEADERS = {
    "User-Agent": (
        "ScopeHunter/0.1 Security-Assessment-Tool "
        "(Authorized Testing; +https://github.com/scopehunter)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


class HttpClient:
    """
    Scoped, rate-limited, async HTTP client.

    All requests pass through:
        ScopeManager → RateLimiter → httpx
    """

    def __init__(
        self,
        scope: ScopeManager,
        rate_limiter: RateLimiter,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.timeout = httpx.Timeout(timeout)
        self._extra_headers = extra_headers or {}
        self._client: httpx.AsyncClient | None = None

        transport_kwargs: dict[str, Any] = {"verify": verify_ssl}
        if proxy:
            transport_kwargs["proxy"] = proxy

        self._client_kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
            "max_redirects": 5,
            "headers": {**DEFAULT_HEADERS, **self._extra_headers},
            **transport_kwargs,
        }

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(**self._client_kwargs)
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        session: SessionProfile | None = None,
        params: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpEvidence:
        """
        Execute a scoped, rate-limited HTTP request.

        Args:
            method: HTTP method (GET, HEAD, OPTIONS, POST).
            url: Target URL.
            session: Optional session profile (cookies + auth headers).
            params: Query parameters.
            json_data: JSON body (POST only).
            form_data: Form data (POST only).
            extra_headers: Per-request headers.

        Returns:
            HttpEvidence snapshot.

        Raises:
            ScopeViolation: If the URL is out of scope.
            httpx.HTTPError: On network/HTTP errors (after retries).
        """
        method = method.upper()

        # Gate 1: Scope enforcement
        self.scope.check(url, method)

        # Gate 2: Rate limiting
        await self.rate_limiter.acquire()

        if not self._client:
            raise RuntimeError("HttpClient must be used as an async context manager.")

        # Build request headers
        headers: dict[str, str] = {}
        if session:
            headers.update(session.to_httpx_headers())
        if extra_headers:
            headers.update(extra_headers)

        # Build cookies from session
        cookies: dict[str, str] = {}
        if session and session.cookies:
            cookies = session.cookies

        logger.debug("[HTTP] %s %s session=%s", method, url, session.name if session else "none")

        return await self._execute_with_retry(
            method, url, headers, cookies, params, json_data, form_data, session
        )

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def _execute_with_retry(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        cookies: dict[str, str],
        params: dict[str, str] | None,
        json_data: dict[str, Any] | None,
        form_data: dict[str, str] | None,
        session: SessionProfile | None,
    ) -> HttpEvidence:
        """Execute HTTP request with automatic retry on transient errors."""
        assert self._client is not None

        t0 = time.monotonic()
        try:
            response = await self._client.request(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                params=params,
                json=json_data,
                data=form_data,
            )
        except httpx.HTTPStatusError as e:
            # HTTPStatusError is not retried — it's a real response
            response = e.response

        elapsed_ms = (time.monotonic() - t0) * 1000

        # Safely extract body snippet
        try:
            body_snippet = response.text[:_BODY_SNIPPET_LIMIT]
        except Exception:
            body_snippet = ""

        return HttpEvidence(
            url=str(response.url),
            method=method,
            request_headers=dict(headers),
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body_snippet=body_snippet,
            response_size=len(response.content),
            elapsed_ms=elapsed_ms,
            session_name=session.name if session else None,
        )

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    async def get(
        self,
        url: str,
        session: SessionProfile | None = None,
        params: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> HttpEvidence:
        return await self.request("GET", url, session=session, params=params, **kwargs)

    async def head(
        self,
        url: str,
        session: SessionProfile | None = None,
    ) -> HttpEvidence:
        return await self.request("HEAD", url, session=session)

    async def options(
        self,
        url: str,
        session: SessionProfile | None = None,
    ) -> HttpEvidence:
        return await self.request("OPTIONS", url, session=session)

    async def post(
        self,
        url: str,
        session: SessionProfile | None = None,
        json_data: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
    ) -> HttpEvidence:
        return await self.request(
            "POST", url, session=session, json_data=json_data, form_data=form_data
        )
