"""
crawler.py — Safe endpoint and parameter discovery crawler.

Discovery sources (all passive/read-only):
    1. HTML links (<a href>)
    2. HTML forms (<form action>, input fields)
    3. JavaScript references (src, fetch(), axios, XMLHttpRequest)
    4. robots.txt
    5. sitemap.xml
    6. API URL patterns in JS files

For each endpoint, we also extract and classify parameters,
identifying potential object identifiers (id, user_id, order_id, etc.)
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from scopehunter.core.evidence import EndpointInfo, HttpEvidence, ParameterInfo
from scopehunter.core.http import HttpClient
from scopehunter.core.scope import ScopeManager

logger = logging.getLogger(__name__)

# Patterns that look like object identifiers
_OBJECT_ID_PARAMS = re.compile(
    r"\b(?:id|user_id|account_id|order_id|profile_id|document_id|"
    r"file_id|project_id|invoice_id|item_id|record_id|object_id|"
    r"product_id|customer_id|ticket_id|message_id|post_id|"
    r"group_id|org_id|team_id|uid|uuid|pid|oid)\b",
    re.IGNORECASE,
)

# Common API URL patterns in JS source
_JS_URL_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.get|axios\.post|api\.get|http\.get)\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](/(?:api|v\d|rest|graphql|endpoint)[^'"`\s]*)['"`]"""),
    re.compile(r"""url\s*:\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""path\s*:\s*['"`]([^'"`\s]+)['"`]"""),
]

# Path parameters like /api/users/{id} or /api/orders/:id
_PATH_PARAM_PATTERN = re.compile(r"\{(\w+)\}|:(\w+)(?=/|$)")


class Crawler:
    """
    Safe, async web crawler for endpoint and parameter discovery.

    Usage:
        crawler = Crawler(client, scope, max_depth=3)
        endpoints = await crawler.crawl("https://target.com")
    """

    def __init__(
        self,
        client: HttpClient,
        scope: ScopeManager,
        max_depth: int = 3,
        max_endpoints: int = 200,
    ) -> None:
        self.client = client
        self.scope = scope
        self.max_depth = max_depth
        self.max_endpoints = max_endpoints
        self._visited: set[str] = set()
        self._endpoints: dict[str, EndpointInfo] = {}

    # ------------------------------------------------------------------
    # Main crawl entry point
    # ------------------------------------------------------------------

    async def crawl(self, start_url: str) -> list[EndpointInfo]:
        """
        BFS crawl starting from start_url.

        Returns discovered endpoints with parameters.
        """
        self._visited.clear()
        self._endpoints.clear()

        # Start with standard discovery sources
        await asyncio.gather(
            self._crawl_robots(start_url),
            self._crawl_sitemap(start_url),
        )

        # BFS crawl
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        self._visited.add(self._normalize(start_url))

        while queue and len(self._endpoints) < self.max_endpoints:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            try:
                evidence = await self.client.get(url)
            except Exception as e:
                logger.debug("Crawler: failed to fetch %s: %s", url, e)
                continue

            self._register_endpoint(url, "GET", evidence, source="crawl")

            if evidence.status_code == 200:
                content_type = evidence.response_headers.get("content-type", "")

                # Parse HTML pages
                if "html" in content_type:
                    new_urls = await self._extract_from_html(
                        url, evidence.response_body_snippet
                    )
                    for new_url in new_urls:
                        norm = self._normalize(new_url)
                        if norm not in self._visited and self.scope.is_in_scope(new_url):
                            self._visited.add(norm)
                            queue.append((new_url, depth + 1))

                # Parse JS files
                elif "javascript" in content_type:
                    self._extract_from_js(url, evidence.response_body_snippet, start_url)

        return list(self._endpoints.values())

    # ------------------------------------------------------------------
    # Specific discovery sources
    # ------------------------------------------------------------------

    async def _crawl_robots(self, base: str) -> None:
        """Parse robots.txt for paths."""
        url = urljoin(base, "/robots.txt")
        try:
            ev = await self.client.get(url)
            if ev.status_code == 200:
                for line in ev.response_body_snippet.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/":
                                full = urljoin(base, path)
                                if self.scope.is_in_scope(full):
                                    self._register_endpoint(
                                        full, "GET", None, source="robots.txt"
                                    )
        except Exception as e:
            logger.debug("robots.txt: %s", e)

    async def _crawl_sitemap(self, base: str) -> None:
        """Parse sitemap.xml for URLs."""
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            url = urljoin(base, path)
            try:
                ev = await self.client.get(url)
                if ev.status_code == 200 and "xml" in ev.response_headers.get("content-type", ""):
                    locs = re.findall(r"<loc>([^<]+)</loc>", ev.response_body_snippet)
                    for loc in locs:
                        loc = loc.strip()
                        if self.scope.is_in_scope(loc):
                            self._register_endpoint(loc, "GET", None, source="sitemap.xml")
            except Exception as e:
                logger.debug("sitemap: %s", e)

    # ------------------------------------------------------------------
    # HTML parsing
    # ------------------------------------------------------------------

    async def _extract_from_html(self, base_url: str, html: str) -> list[str]:
        """Extract links and forms from HTML."""
        new_urls: list[str] = []
        soup = BeautifulSoup(html, "lxml")

        # Extract <a href> links
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(base_url, href)
            new_urls.append(full)

        # Extract <form> actions and their fields
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "GET")).upper()
            full_action = urljoin(base_url, str(action)) if action else base_url

            params: list[ParameterInfo] = []
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name", "")
                if name:
                    params.append(
                        ParameterInfo(
                            name=name,
                            location="body" if method == "POST" else "query",
                            is_object_identifier=bool(_OBJECT_ID_PARAMS.match(name)),
                        )
                    )

            if self.scope.is_in_scope(full_action):
                self._register_endpoint(
                    full_action, method, None, source="form", params=params
                )
                new_urls.append(full_action)

        # Extract <script src> references
        for script in soup.find_all("script", src=True):
            src = str(script["src"]).strip()
            full_src = urljoin(base_url, src)
            if self.scope.is_in_scope(full_src):
                new_urls.append(full_src)

        return new_urls

    # ------------------------------------------------------------------
    # JavaScript parsing
    # ------------------------------------------------------------------

    def _extract_from_js(self, js_url: str, js_content: str, base: str) -> None:
        """Extract API endpoint patterns from JavaScript source."""
        for pattern in _JS_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                if not path or len(path) > 200:
                    continue
                # Skip obvious non-URLs
                if any(x in path for x in ["//", "http://", "https://", "data:", "blob:"]):
                    if not path.startswith(("http://", "https://")):
                        continue
                    full = path
                else:
                    full = urljoin(base, path)

                if self.scope.is_in_scope(full):
                    self._register_endpoint(full, "GET", None, source=f"js:{js_url}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _register_endpoint(
        self,
        url: str,
        method: str,
        evidence: HttpEvidence | None,
        source: str,
        params: list[ParameterInfo] | None = None,
    ) -> None:
        """Register or update an endpoint in the discovered map."""
        key = f"{method}:{self._normalize(url)}"
        if key in self._endpoints:
            return

        # Extract query parameters from URL
        parsed = urlparse(url)
        qp_params: list[ParameterInfo] = []
        if parsed.query:
            for name in parse_qs(parsed.query):
                qp_params.append(
                    ParameterInfo(
                        name=name,
                        location="query",
                        value_example=parse_qs(parsed.query)[name][0],
                        is_object_identifier=bool(_OBJECT_ID_PARAMS.match(name)),
                    )
                )

        # Extract path parameters
        path_params: list[ParameterInfo] = []
        for m in _PATH_PARAM_PATTERN.finditer(parsed.path):
            name = m.group(1) or m.group(2)
            path_params.append(
                ParameterInfo(
                    name=name,
                    location="path",
                    is_object_identifier=bool(_OBJECT_ID_PARAMS.match(name)),
                )
            )

        all_params = (params or []) + qp_params + path_params

        self._endpoints[key] = EndpointInfo(
            url=url,
            method=method,
            parameters=all_params,
            source=source,
            status_code=evidence.status_code if evidence else None,
            response_size=evidence.response_size if evidence else None,
            content_type=evidence.response_headers.get("content-type") if evidence else None,
        )

    @staticmethod
    def _normalize(url: str) -> str:
        """Normalize URL for deduplication (strip fragments, trailing slash)."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
