"""
scope.py — Scope enforcement layer.

Every outgoing request MUST pass through ScopeManager.check() before execution.
This is the first gate in the pipeline:

    ScopeManager.check()
        ↓
    RateLimiter
        ↓
    HTTP Request
        ↓
    Evidence
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract


@dataclass
class ScopeRule:
    """A single scope rule that matches URLs."""

    pattern: str  # e.g. "*.example.com", "example.com/api/*", "10.0.0.1"
    allow_subdomains: bool = True
    _compiled: re.Pattern | None = field(default=None, init=False, repr=False)

    def _compile(self) -> re.Pattern:
        if self._compiled is None:
            escaped = re.escape(self.pattern)
            # Convert wildcard * to regex .*
            regex = escaped.replace(r"\*", r"[^/]*")
            self._compiled = re.compile(f"^{regex}$", re.IGNORECASE)
        return self._compiled

    def matches_host(self, host: str) -> bool:
        """Check if a hostname matches this scope rule."""
        pattern = self._compile()
        if pattern.match(host):
            return True
        # If the rule is a bare domain and allow_subdomains is True,
        # also match *.rule_domain
        if self.allow_subdomains and not self.pattern.startswith("*"):
            subdomain_pattern = re.compile(
                r"^[a-zA-Z0-9\-\.]+\." + re.escape(self.pattern) + r"$",
                re.IGNORECASE,
            )
            return bool(subdomain_pattern.match(host))
        return False


class ScopeViolation(Exception):
    """Raised when a request target is out of scope."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"OUT OF SCOPE: {url} — {reason}")


class ScopeManager:
    """
    Strict scope enforcement for all outgoing requests.

    Usage:
        scope = ScopeManager(target="https://example.com", allowed=["example.com"])
        scope.check("https://example.com/api/users")       # OK
        scope.check("https://evil.com/steal")              # raises ScopeViolation
    """

    # HTTP methods that are always blocked (destructive)
    BLOCKED_METHODS: frozenset[str] = frozenset(
        {"DELETE", "PATCH", "PUT", "CONNECT", "TRACE"}
    )

    # Paths that should never be requested
    BLOCKED_PATH_PATTERNS: list[re.Pattern] = [
        re.compile(r"/wp-admin/admin-ajax\.php\?action=delete", re.IGNORECASE),
        re.compile(r"/admin/users/\d+/delete", re.IGNORECASE),
        re.compile(r"/api/.*/delete", re.IGNORECASE),
    ]

    def __init__(
        self,
        target: str,
        allowed_scope: list[str] | None = None,
        allow_subdomains: bool = True,
    ) -> None:
        """
        Args:
            target: Primary target URL (e.g. "https://example.com").
            allowed_scope: List of additional scope rules.
                           If None, only the target domain is in scope.
            allow_subdomains: Whether subdomains of the target are in scope.
        """
        self.target = target.rstrip("/")
        parsed = urlparse(target)
        self.target_host = parsed.hostname or ""
        self.target_scheme = parsed.scheme

        # Build scope rules
        self._rules: list[ScopeRule] = []

        # Primary target is always in scope
        extracted = tldextract.extract(self.target_host)
        primary_domain = f"{extracted.domain}.{extracted.suffix}"
        self._rules.append(ScopeRule(primary_domain, allow_subdomains=allow_subdomains))

        # Add explicit scope overrides
        if allowed_scope:
            for rule in allowed_scope:
                rule = rule.strip()
                if rule:
                    self._rules.append(ScopeRule(rule, allow_subdomains=allow_subdomains))

        self._violation_log: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, url: str, method: str = "GET") -> None:
        """
        Validate a URL + method against scope rules.

        Raises:
            ScopeViolation: If the URL is out of scope or method is blocked.
        """
        method = method.upper()

        # Block destructive HTTP methods
        if method in self.BLOCKED_METHODS:
            raise ScopeViolation(url, f"HTTP method '{method}' is blocked (destructive).")

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        # Must have a valid scheme
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation(url, f"Unsupported scheme '{parsed.scheme}'.")

        # Check blocked path patterns
        for blocked in self.BLOCKED_PATH_PATTERNS:
            if blocked.search(path):
                raise ScopeViolation(url, f"Path matches blocked pattern: {blocked.pattern}")

        # Check host against all scope rules
        if not any(rule.matches_host(host) for rule in self._rules):
            self._violation_log.append(url)
            raise ScopeViolation(url, f"Host '{host}' is not in scope.")

    def is_in_scope(self, url: str, method: str = "GET") -> bool:
        """Return True if the URL is in scope, False otherwise (no exception)."""
        try:
            self.check(url, method)
            return True
        except ScopeViolation:
            return False

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs, returning only in-scope ones."""
        return [u for u in urls if self.is_in_scope(u)]

    @property
    def violation_count(self) -> int:
        return len(self._violation_log)

    def __repr__(self) -> str:
        rules_str = ", ".join(r.pattern for r in self._rules)
        return f"ScopeManager(target={self.target!r}, rules=[{rules_str}])"
