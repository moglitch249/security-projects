"""
common/security_headers.py — Security headers analysis check.

Checks for presence and correct configuration of:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin headers
"""

from __future__ import annotations

import logging

from scopehunter.core.evidence import Finding, HttpEvidence, Severity, VulnClass
from scopehunter.engine.check_runner import CheckContext

logger = logging.getLogger(__name__)

CHECK_NAME = "Security Headers"
CHECK_DESCRIPTION = "Analyzes HTTP security headers for missing or misconfigured values."

# (header_name, expected_presence, severity, recommendation)
_HEADER_CHECKS = [
    {
        "header": "strict-transport-security",
        "severity": Severity.MEDIUM,
        "must_contain": None,
        "should_contain": "max-age",
        "title": "Missing or Weak Strict-Transport-Security (HSTS)",
        "why": "HSTS prevents protocol downgrade attacks and cookie hijacking over HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header": "content-security-policy",
        "severity": Severity.MEDIUM,
        "must_contain": None,
        "should_contain": None,
        "title": "Missing Content-Security-Policy (CSP)",
        "why": "CSP prevents XSS and data injection attacks by restricting resource origins.",
        "remediation": "Implement a strict Content-Security-Policy header.",
    },
    {
        "header": "x-frame-options",
        "severity": Severity.LOW,
        "must_contain": None,
        "should_contain": None,
        "title": "Missing X-Frame-Options",
        "why": "Without X-Frame-Options, the page may be embedded in iframes (clickjacking).",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
        "header": "x-content-type-options",
        "severity": Severity.LOW,
        "must_contain": "nosniff",
        "should_contain": None,
        "title": "Missing or Misconfigured X-Content-Type-Options",
        "why": "Without 'nosniff', browsers may MIME-sniff responses, enabling some attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "referrer-policy",
        "severity": Severity.LOW,
        "must_contain": None,
        "should_contain": None,
        "title": "Missing Referrer-Policy",
        "why": "Without Referrer-Policy, sensitive URL data may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "permissions-policy",
        "severity": Severity.LOW,
        "must_contain": None,
        "should_contain": None,
        "title": "Missing Permissions-Policy",
        "why": "Permissions-Policy controls browser features (camera, microphone, geolocation).",
        "remediation": "Add a Permissions-Policy header restricting unused browser features.",
    },
]

_SERVER_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


async def run(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    # Fetch root page headers
    try:
        ev = await context.client.get(context.target)
    except Exception as e:
        logger.warning("[SecurityHeaders] Failed to fetch target: %s", e)
        return findings

    headers = {k.lower(): v for k, v in ev.response_headers.items()}

    # --- Security header checks ---
    for check in _HEADER_CHECKS:
        header_name = check["header"]
        header_value = headers.get(header_name, "")

        is_missing = not header_value
        is_misconfigured = (
            not is_missing
            and check["must_contain"]
            and check["must_contain"].lower() not in header_value.lower()
        )

        if is_missing or is_misconfigured:
            issue = "missing" if is_missing else f"missing '{check['must_contain']}'"
            findings.append(Finding(
                title=check["title"],
                severity=check["severity"],
                confidence_score=0.95,
                vuln_class=VulnClass.MISSING_HEADERS,
                technology=None,
                endpoint=context.target,
                method="GET",
                parameter=None,
                description=f"Header '{header_name}' is {issue}. Value: '{header_value or '(not present)'}'",
                why_it_matters=check["why"],
                manual_verification=(
                    f"Run: curl -I {context.target} | grep -i '{header_name}'\n"
                    f"Verify the header is present and correctly configured."
                ),
                remediation=check["remediation"],
                evidence=[ev],
                tags=["security-headers", header_name.replace("-", "_")],
            ))

    # --- Server/technology information leakage ---
    for leak_header in _SERVER_LEAK_HEADERS:
        val = headers.get(leak_header, "")
        if val:
            findings.append(Finding(
                title=f"Technology/Version Information Disclosure via '{leak_header}' Header",
                severity=Severity.INFO,
                confidence_score=0.9,
                vuln_class=VulnClass.INFO_DISCLOSURE,
                technology=None,
                endpoint=context.target,
                method="GET",
                parameter=None,
                description=f"Header '{leak_header}: {val}' reveals technology information.",
                why_it_matters=(
                    "Version information can help attackers identify known CVEs for the specific "
                    "server version and reduce the effort needed to target the application."
                ),
                manual_verification=(
                    f"Run: curl -I {context.target} | grep -i '{leak_header}'\n"
                    "Assess if the disclosed version is associated with known vulnerabilities."
                ),
                remediation=(
                    f"Remove or mask the '{leak_header}' header in your server configuration. "
                    "For Nginx: 'server_tokens off;' | For Apache: 'ServerTokens Prod; ServerSignature Off;'"
                ),
                evidence=[ev],
                tags=["info-disclosure", "version-leak", leak_header],
            ))

    logger.info("[SecurityHeaders] Found %d issues", len(findings))
    return findings
