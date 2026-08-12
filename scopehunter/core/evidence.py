"""
evidence.py — Data models for findings, evidence, and session profiles.

All findings require:
- A confidence score (0.0–1.0)
- At least one piece of evidence
- A manual verification step
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(str, Enum):
    HIGH = "high"      # >= 0.8
    MEDIUM = "medium"  # >= 0.5
    LOW = "low"        # < 0.5

    @staticmethod
    def from_score(score: float) -> "Confidence":
        if score >= 0.8:
            return Confidence.HIGH
        elif score >= 0.5:
            return Confidence.MEDIUM
        return Confidence.LOW


class VulnClass(str, Enum):
    BAC = "Broken Access Control"
    IDOR = "IDOR / BOLA"
    AUTH_MISCONFIG = "Authentication Misconfiguration"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    INFO_DISCLOSURE = "Information Disclosure"
    CORS = "CORS Misconfiguration"
    MISSING_HEADERS = "Missing Security Headers"
    EXPOSED_DOCS = "Exposed Documentation"
    EXPOSED_DEBUG = "Exposed Debug Information"
    SENSITIVE_FILES = "Sensitive File Exposure"
    OPEN_REDIRECT = "Open Redirect"
    SSRF = "SSRF Indicator"
    XSS_INDICATOR = "XSS Indicator"
    SQLI_INDICATOR = "SQL Injection Indicator"
    PATH_TRAVERSAL = "Path Traversal Indicator"
    RATE_LIMIT = "Rate Limiting Observation"
    CVE_APPLICABLE = "Potentially Applicable CVE"
    GENERIC = "Generic Finding"


# ---------------------------------------------------------------------------
# Session / Authentication Profiles
# ---------------------------------------------------------------------------


@dataclass
class SessionProfile:
    """
    Represents one authenticated session for authorization testing.

    Supports cookies, bearer tokens, and custom headers.
    """

    name: str                                      # e.g. "owner", "another_user", "admin"
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    description: str = ""

    def to_httpx_headers(self) -> dict[str, str]:
        """Merge bearer token into headers dict."""
        hdrs = dict(self.headers)
        if self.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.bearer_token}"
        return hdrs


# ---------------------------------------------------------------------------
# HTTP evidence snapshot
# ---------------------------------------------------------------------------


@dataclass
class HttpEvidence:
    """Snapshot of a single HTTP request/response pair."""

    url: str
    method: str
    request_headers: dict[str, str]
    status_code: int
    response_headers: dict[str, str]
    response_body_snippet: str        # First 512 chars max
    response_size: int
    elapsed_ms: float
    session_name: str | None = None   # Which session profile was used

    @property
    def short_repr(self) -> str:
        return f"{self.method} {self.url} → {self.status_code} ({self.response_size}B)"


# ---------------------------------------------------------------------------
# Parameter descriptor
# ---------------------------------------------------------------------------


@dataclass
class ParameterInfo:
    """Describes a discovered parameter on an endpoint."""

    name: str
    location: str                   # "query", "path", "body", "header", "cookie"
    value_example: str | None = None
    is_object_identifier: bool = False  # True for id, user_id, order_id, etc.
    inferred_type: str | None = None    # "integer", "uuid", "string", etc.


# ---------------------------------------------------------------------------
# Discovered endpoint
# ---------------------------------------------------------------------------


@dataclass
class EndpointInfo:
    """A discovered endpoint with full metadata."""

    url: str
    method: str = "GET"
    parameters: list[ParameterInfo] = field(default_factory=list)
    source: str = "unknown"          # "crawl", "robots.txt", "sitemap", "js", "forms"
    status_code: int | None = None
    response_size: int | None = None
    content_type: str | None = None
    requires_auth: bool | None = None
    technology: str | None = None
    confidence: float = 0.5
    notes: str = ""

    @property
    def has_object_identifiers(self) -> bool:
        return any(p.is_object_identifier for p in self.parameters)


# ---------------------------------------------------------------------------
# Technology detection result
# ---------------------------------------------------------------------------


@dataclass
class TechDetection:
    """Result of a single technology fingerprint match."""

    technology: str
    confidence: float               # 0.0–1.0
    version: str | None = None
    evidence: list[str] = field(default_factory=list)  # Which signals fired


# ---------------------------------------------------------------------------
# CVE applicability record
# ---------------------------------------------------------------------------


@dataclass
class CveApplicability:
    """
    Represents a potentially applicable CVE based on detected version.
    The tool NEVER exploits CVEs. It only flags for manual verification.
    """

    cve_id: str
    affected_component: str
    affected_versions: str          # e.g. "<= 6.4.2"
    detected_version: str | None
    confidence: Confidence
    description: str
    reference_url: str | None = None


# ---------------------------------------------------------------------------
# Core Finding model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A security finding with full evidence and manual verification guidance.

    Findings are NEVER reported as confirmed unless confidence >= HIGH and
    multiple evidence points exist.
    """

    title: str
    severity: Severity
    confidence_score: float          # 0.0–1.0
    vuln_class: VulnClass
    technology: str | None
    endpoint: str
    method: str
    parameter: str | None
    description: str
    why_it_matters: str
    manual_verification: str
    remediation: str
    evidence: list[HttpEvidence] = field(default_factory=list)
    cve: CveApplicability | None = None
    false_positive_notes: str = ""
    tags: list[str] = field(default_factory=list)
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def confidence(self) -> Confidence:
        return Confidence.from_score(self.confidence_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_score": round(self.confidence_score, 2),
            "vuln_class": self.vuln_class.value,
            "technology": self.technology,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "description": self.description,
            "why_it_matters": self.why_it_matters,
            "manual_verification": self.manual_verification,
            "remediation": self.remediation,
            "evidence": [
                {
                    "url": e.url,
                    "method": e.method,
                    "status_code": e.status_code,
                    "response_size": e.response_size,
                    "elapsed_ms": round(e.elapsed_ms, 1),
                    "session": e.session_name,
                    "snippet": e.response_body_snippet[:256],
                }
                for e in self.evidence
            ],
            "cve": (
                {
                    "id": self.cve.cve_id,
                    "component": self.cve.affected_component,
                    "affected_versions": self.cve.affected_versions,
                    "detected_version": self.cve.detected_version,
                    "confidence": self.cve.confidence.value,
                }
                if self.cve
                else None
            ),
            "tags": self.tags,
            "discovered_at": self.discovered_at.isoformat(),
        }
