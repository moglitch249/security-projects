"""
common/cors.py — CORS misconfiguration detection.

Checks for:
- Wildcard ACAO with credentials
- Reflected Origin
- Null origin acceptance
- Misconfigured trusted origins
"""

from __future__ import annotations

import logging

from scopehunter.core.evidence import Finding, Severity, VulnClass
from scopehunter.engine.check_runner import CheckContext

logger = logging.getLogger(__name__)

CHECK_NAME = "CORS Misconfiguration"
CHECK_DESCRIPTION = "Detects Cross-Origin Resource Sharing misconfigurations."

_TEST_ORIGINS = [
    "https://evil.scopehunter-test.com",
    "null",
]


async def run(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    for origin in _TEST_ORIGINS:
        try:
            ev = await context.client.get(
                context.target,
                extra_headers={"Origin": origin}
            )
        except Exception as e:
            logger.debug("[CORS] Request failed: %s", e)
            continue

        acao = ev.response_headers.get("access-control-allow-origin", "")
        acac = ev.response_headers.get("access-control-allow-credentials", "")

        if not acao:
            continue

        # Check 1: Wildcard with credentials
        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                title="CORS: Wildcard Origin with Allow-Credentials",
                severity=Severity.HIGH,
                confidence_score=0.95,
                vuln_class=VulnClass.CORS,
                technology=None,
                endpoint=context.target,
                method="GET",
                parameter=None,
                description=(
                    "The server responds with 'Access-Control-Allow-Origin: *' and "
                    "'Access-Control-Allow-Credentials: true'. "
                    "Browsers block this combination, but it indicates misconfiguration."
                ),
                why_it_matters=(
                    "If credentials are allowed with a wildcard origin, any website could "
                    "potentially make authenticated cross-origin requests."
                ),
                manual_verification=(
                    f"curl -H 'Origin: https://evil.example.com' -I {context.target}\n"
                    "Check the ACAO and ACAC headers in the response."
                ),
                remediation=(
                    "Never combine 'Access-Control-Allow-Origin: *' with "
                    "'Access-Control-Allow-Credentials: true'. "
                    "Maintain an explicit allowlist of trusted origins."
                ),
                evidence=[ev],
                tags=["cors", "misconfiguration"],
            ))

        # Check 2: Reflected origin
        elif acao == origin and origin != "null":
            confidence = 0.75 if acac.lower() == "true" else 0.5
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            findings.append(Finding(
                title=f"CORS: Origin Reflected{'  with Credentials' if acac.lower() == 'true' else ''}",
                severity=severity,
                confidence_score=confidence,
                vuln_class=VulnClass.CORS,
                technology=None,
                endpoint=context.target,
                method="GET",
                parameter=None,
                description=(
                    f"Server reflects arbitrary origin '{origin}' in "
                    f"Access-Control-Allow-Origin. "
                    f"Allow-Credentials: {acac or 'not set'}."
                ),
                why_it_matters=(
                    "A reflected ACAO without proper validation allows any origin to "
                    "make cross-origin requests. With credentials, this is critical."
                ),
                manual_verification=(
                    f"curl -H 'Origin: https://evil.example.com' -I {context.target}\n"
                    "Verify that the response ACAO header reflects the sent origin."
                ),
                remediation=(
                    "Validate the Origin header against a strict server-side allowlist. "
                    "Do not dynamically reflect any origin value."
                ),
                evidence=[ev],
                tags=["cors", "reflected-origin"],
            ))

        # Check 3: Null origin accepted
        elif origin == "null" and acao == "null":
            findings.append(Finding(
                title="CORS: Null Origin Accepted",
                severity=Severity.MEDIUM,
                confidence_score=0.8,
                vuln_class=VulnClass.CORS,
                technology=None,
                endpoint=context.target,
                method="GET",
                parameter=None,
                description="Server accepts 'null' as a valid CORS origin.",
                why_it_matters=(
                    "The 'null' origin can be spoofed via sandboxed iframes, "
                    "enabling cross-origin data theft in some browser configurations."
                ),
                manual_verification=(
                    f"curl -H 'Origin: null' -I {context.target}\n"
                    "Confirm ACAO: null in the response."
                ),
                remediation="Remove 'null' from your allowed origins list.",
                evidence=[ev],
                tags=["cors", "null-origin"],
            ))

    logger.info("[CORS] Found %d issues", len(findings))
    return findings
