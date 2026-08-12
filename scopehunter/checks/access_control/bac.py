"""
access_control/bac.py — Broken Access Control & IDOR/BOLA detection.

IMPORTANT: This check is PURELY PASSIVE and SAFE:
- Only performs READ requests (GET/HEAD)
- Never modifies, deletes, or creates data
- Requires TWO explicitly authorized session profiles
- Reports only when there is strong multi-signal evidence

Detection logic:
    1. Find endpoints with object-level identifiers (id, user_id, order_id, etc.)
    2. Request each endpoint with Session A (owner)
    3. Request the SAME endpoint with Session B (another_user)
    4. Compare: status code, response structure, ownership fields
    5. Flag only when B successfully receives A's data with high confidence
"""

from __future__ import annotations

import json
import logging
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from scopehunter.core.evidence import (
    Confidence,
    Finding,
    HttpEvidence,
    Severity,
    VulnClass,
)
from scopehunter.engine.check_runner import CheckContext

logger = logging.getLogger(__name__)

CHECK_NAME = "Broken Access Control / IDOR"
CHECK_DESCRIPTION = (
    "Detects broken access control and IDOR/BOLA vulnerabilities using "
    "safe dual-session comparison. Requires at least 2 session profiles."
)

# Patterns indicating ownership fields in JSON responses
_OWNER_FIELD_PATTERNS = re.compile(
    r"(?:user_?id|owner_?id|account_?id|author_?id|created_?by|"
    r"belongs_?to|member_?id|customer_?id)\b",
    re.IGNORECASE,
)

# Status codes that definitively mean "not authorized"
_DENIED_STATUSES = {401, 403, 404, 405, 429}

# Status codes that indicate access
_ACCESS_GRANTED_STATUSES = {200, 201, 206}


async def run(context: CheckContext) -> list[Finding]:
    """
    Execute the dual-session access control check.

    Returns a list of findings with strong evidence only.
    """
    findings: list[Finding] = []

    sessions = context.sessions
    if len(sessions) < 2:
        logger.info(
            "[BAC] Skipping: requires at least 2 session profiles, got %d", len(sessions)
        )
        return findings

    # Identify session pairs (horizontal and vertical)
    session_pairs = _build_session_pairs(sessions)

    # Find endpoints with object identifiers
    candidate_endpoints = [
        ep for ep in context.endpoints
        if ep.has_object_identifiers or _url_has_numeric_segment(ep.url)
    ]

    logger.info(
        "[BAC] %d candidate endpoints, %d session pairs",
        len(candidate_endpoints),
        len(session_pairs),
    )

    for ep in candidate_endpoints:
        for session_a, session_b in session_pairs:
            finding = await _compare_access(
                context, ep.url, ep.method, session_a, session_b
            )
            if finding:
                findings.append(finding)

    return findings


async def _compare_access(
    context: CheckContext,
    url: str,
    method: str,
    session_a,
    session_b,
) -> Finding | None:
    """
    Compare access between two sessions for the same resource.

    Returns a Finding only if there is strong multi-signal evidence.
    """
    client = context.client

    # --- Request with Session A (owner) ---
    try:
        ev_a = await client.request(method, url, session=session_a)
    except Exception as e:
        logger.debug("[BAC] Session A request failed: %s", e)
        return None

    # If A gets denied, this isn't a useful comparison baseline
    if ev_a.status_code not in _ACCESS_GRANTED_STATUSES:
        return None

    # --- Request with Session B (other) ---
    try:
        ev_b = await client.request(method, url, session=session_b)
    except Exception as e:
        logger.debug("[BAC] Session B request failed: %s", e)
        return None

    # --- Analyze ---
    analysis = _analyze_responses(ev_a, ev_b, session_a, session_b)

    if analysis is None:
        return None

    confidence_score, issue_type, description = analysis

    if confidence_score < 0.5:
        return None

    return Finding(
        title=f"Possible {issue_type}",
        severity=_severity_from_issue(issue_type),
        confidence_score=confidence_score,
        vuln_class=_vuln_class_from_issue(issue_type),
        technology=None,
        endpoint=url,
        method=method,
        parameter=_extract_id_param(url),
        description=description,
        why_it_matters=(
            "If Session B (another user) can access resources belonging to Session A "
            "without authorization, it indicates a broken access control vulnerability. "
            "This may allow data leakage, account takeover, or business logic bypass."
        ),
        manual_verification=(
            f"1. Log in as '{session_a.name}' and note the resource ID in this URL.\n"
            f"2. Log in as '{session_b.name}' (a different account with no ownership).\n"
            f"3. Request: {method} {url}\n"
            f"4. Confirm that '{session_b.name}' should NOT have access to this object.\n"
            f"5. If response is 200 with the owner's data, this is confirmed IDOR/BAC."
        ),
        remediation=(
            "Implement object-level authorization checks on every resource endpoint. "
            "Verify that the authenticated user owns or has explicit permission to access "
            "the requested object. Do not rely solely on authentication — check authorization."
        ),
        evidence=[ev_a, ev_b],
        false_positive_notes=(
            "This could be a false positive if: (a) the resource is intentionally public, "
            "(b) both users belong to the same organization/group, or "
            "(c) the response content is generic and not user-specific."
        ),
        tags=["access-control", "idor", "bola", "authorization"],
    )


def _analyze_responses(
    ev_a: HttpEvidence,
    ev_b: HttpEvidence,
    session_a,
    session_b,
) -> tuple[float, str, str] | None:
    """
    Multi-signal analysis to determine if B accessed A's data.

    Returns (confidence_score, issue_type, description) or None.
    """
    signals: list[tuple[float, str]] = []

    # Signal 1: Status code — B gets 200 where A gets 200
    if ev_b.status_code in _ACCESS_GRANTED_STATUSES:
        signals.append((0.4, f"Session B received HTTP {ev_b.status_code}"))
    elif ev_b.status_code in _DENIED_STATUSES:
        # B was properly denied — no issue
        return None

    # Signal 2: Response size similarity
    size_ratio = _size_ratio(ev_a.response_size, ev_b.response_size)
    if size_ratio > 0.85:
        signals.append((0.3, f"Response size similar ({ev_a.response_size}B vs {ev_b.response_size}B)"))

    # Signal 3: Content similarity
    similarity = SequenceMatcher(
        None, ev_a.response_body_snippet, ev_b.response_body_snippet
    ).ratio()
    if similarity > 0.7:
        signals.append((0.3, f"Response content {similarity:.0%} similar"))

    # Signal 4: JSON structure + ownership field matching
    json_signal = _check_json_ownership(ev_a.response_body_snippet, ev_b.response_body_snippet)
    if json_signal:
        signals.append(json_signal)

    if not signals or len(signals) < 2:
        return None

    confidence = min(sum(s[0] for s in signals), 1.0)
    evidence_desc = "; ".join(s[1] for s in signals)

    # Determine issue type
    a_name = session_a.name.lower()
    b_name = session_b.name.lower()
    if "admin" in a_name or "admin" in b_name:
        issue_type = "Vertical Privilege Escalation"
    else:
        issue_type = "IDOR / Broken Access Control (Horizontal)"

    description = (
        f"Session '{session_b.name}' appears to access a resource belonging to "
        f"Session '{session_a.name}'.\n\nEvidence: {evidence_desc}"
    )

    return confidence, issue_type, description


def _check_json_ownership(body_a: str, body_b: str) -> tuple[float, str] | None:
    """Check if JSON responses contain matching ownership-field values."""
    try:
        data_a = json.loads(body_a)
        data_b = json.loads(body_b)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data_a, dict) or not isinstance(data_b, dict):
        return None

    # Look for matching ID fields
    for key in data_a:
        if _OWNER_FIELD_PATTERNS.search(key):
            val_a = data_a.get(key)
            val_b = data_b.get(key)
            if val_a is not None and val_a == val_b:
                return (0.5, f"Ownership field '{key}' matches: {val_a!r}")

    return None


def _size_ratio(size_a: int, size_b: int) -> float:
    if size_a == 0 and size_b == 0:
        return 1.0
    if size_a == 0 or size_b == 0:
        return 0.0
    return min(size_a, size_b) / max(size_a, size_b)


def _url_has_numeric_segment(url: str) -> bool:
    """Check if URL contains numeric path segments (likely object IDs)."""
    path = urlparse(url).path
    return bool(re.search(r"/\d+(?:/|$)", path))


def _extract_id_param(url: str) -> str | None:
    """Extract the identifier from a URL path or query string."""
    path = urlparse(url).path
    m = re.search(r"/(\d+)(?:/|$)", path)
    if m:
        return f"id={m.group(1)}"
    return None


def _severity_from_issue(issue_type: str) -> Severity:
    if "Vertical" in issue_type:
        return Severity.CRITICAL
    return Severity.HIGH


def _vuln_class_from_issue(issue_type: str) -> VulnClass:
    if "Vertical" in issue_type:
        return VulnClass.BAC
    return VulnClass.IDOR


def _build_session_pairs(sessions) -> list[tuple]:
    """Build all meaningful session comparison pairs."""
    pairs = []
    for i, a in enumerate(sessions):
        for b in sessions[i + 1:]:
            pairs.append((a, b))
            pairs.append((b, a))
    return pairs
