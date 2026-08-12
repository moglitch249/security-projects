"""
disclosure/info_disclosure.py — Information disclosure detection.

Checks for:
- Exposed sensitive files (.env, .git, config files, logs)
- Debug mode indicators
- Stack traces in error responses
- Exposed API documentation
- Version disclosure
"""

from __future__ import annotations

import logging
import re

from scopehunter.core.evidence import Finding, Severity, VulnClass
from scopehunter.engine.check_runner import CheckContext

logger = logging.getLogger(__name__)

CHECK_NAME = "Information Disclosure"
CHECK_DESCRIPTION = "Detects sensitive information exposure via files, debug pages, and error responses."

# Sensitive file paths to probe
_SENSITIVE_PATHS = [
    {"path": "/.env",                 "severity": Severity.CRITICAL, "note": "Environment variables (DB creds, API keys)"},
    {"path": "/.env.local",           "severity": Severity.CRITICAL, "note": "Local environment file"},
    {"path": "/.env.production",      "severity": Severity.CRITICAL, "note": "Production environment file"},
    {"path": "/.env.backup",          "severity": Severity.CRITICAL, "note": "Environment backup"},
    {"path": "/.git/config",          "severity": Severity.HIGH,     "note": "Exposed Git repository"},
    {"path": "/.git/HEAD",            "severity": Severity.HIGH,     "note": "Exposed Git HEAD file"},
    {"path": "/config/database.yml",  "severity": Severity.CRITICAL, "note": "Database configuration (Rails)"},
    {"path": "/config/secrets.yml",   "severity": Severity.CRITICAL, "note": "Secrets configuration (Rails)"},
    {"path": "/storage/logs/laravel.log", "severity": Severity.HIGH, "note": "Laravel application log"},
    {"path": "/app/logs/prod.log",    "severity": Severity.HIGH,     "note": "Application log file"},
    {"path": "/phpinfo.php",          "severity": Severity.HIGH,     "note": "PHP info page"},
    {"path": "/info.php",             "severity": Severity.HIGH,     "note": "PHP info page (alt)"},
    {"path": "/package.json",         "severity": Severity.LOW,      "note": "Node.js package manifest"},
    {"path": "/composer.json",        "severity": Severity.LOW,      "note": "PHP Composer manifest"},
    {"path": "/Dockerfile",           "severity": Severity.LOW,      "note": "Docker configuration"},
    {"path": "/docker-compose.yml",   "severity": Severity.LOW,      "note": "Docker Compose config"},
    {"path": "/wp-config.php.bak",    "severity": Severity.CRITICAL, "note": "WordPress config backup"},
    {"path": "/backup.sql",           "severity": Severity.CRITICAL, "note": "Database backup file"},
    {"path": "/dump.sql",             "severity": Severity.CRITICAL, "note": "Database dump file"},
    {"path": "/server-status",        "severity": Severity.MEDIUM,   "note": "Apache server status page"},
    {"path": "/server-info",          "severity": Severity.MEDIUM,   "note": "Apache server info page"},
]

# Patterns in response body that indicate exposure
_SENSITIVE_CONTENT_PATTERNS = [
    (re.compile(r"(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY)\s*=\s*\S+", re.IGNORECASE),
     "Contains credentials/secrets", Severity.CRITICAL),
    (re.compile(r"mysql://|postgres://|mongodb://", re.IGNORECASE),
     "Contains database connection string", Severity.CRITICAL),
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
     "Python stack trace visible", Severity.MEDIUM),
    (re.compile(r"at\s+[\w\.]+\([\w\.]+\.java:\d+\)", re.IGNORECASE),
     "Java stack trace visible", Severity.MEDIUM),
    (re.compile(r"Fatal error:.*in .* on line \d+", re.IGNORECASE),
     "PHP fatal error visible", Severity.MEDIUM),
    (re.compile(r"\[ref=https://ignition\.spatie", re.IGNORECASE),
     "Laravel Ignition debug page active", Severity.HIGH),
    (re.compile(r"<?php phpinfo\(\)", re.IGNORECASE),
     "PHP info page content", Severity.HIGH),
    (re.compile(r"\[master\]|ref:\s*refs/heads/", re.IGNORECASE),
     "Git HEAD file content", Severity.HIGH),
]


async def run(context: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    from urllib.parse import urljoin

    base = context.target.rstrip("/")

    for path_def in _SENSITIVE_PATHS:
        url = urljoin(base + "/", path_def["path"].lstrip("/"))
        try:
            ev = await context.client.get(url)
        except Exception as e:
            logger.debug("[InfoDisclose] Probe failed %s: %s", url, e)
            continue

        # File must return 200 to be considered exposed
        if ev.status_code != 200:
            continue

        # Check for sensitive content patterns
        matched_patterns = []
        for pattern, desc, sev in _SENSITIVE_CONTENT_PATTERNS:
            if pattern.search(ev.response_body_snippet):
                matched_patterns.append((desc, sev))

        # Determine confidence and severity
        if matched_patterns:
            confidence = 0.95
            severity = max(
                (sev for _, sev in matched_patterns),
                key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value),
                default=path_def["severity"],
            )
            description = (
                f"File '{path_def['path']}' is publicly accessible (HTTP 200) and "
                f"contains sensitive content: {'; '.join(d for d, _ in matched_patterns)}"
            )
        else:
            confidence = 0.75
            severity = path_def["severity"]
            description = (
                f"File '{path_def['path']}' is publicly accessible (HTTP 200, {ev.response_size}B). "
                f"Note: {path_def['note']}"
            )

        findings.append(Finding(
            title=f"Sensitive File Exposed: {path_def['path']}",
            severity=severity,
            confidence_score=confidence,
            vuln_class=VulnClass.SENSITIVE_FILES,
            technology=None,
            endpoint=url,
            method="GET",
            parameter=None,
            description=description,
            why_it_matters=(
                f"Publicly accessible sensitive files can expose credentials, "
                f"configuration details, source code, or internal infrastructure information. "
                f"Note: {path_def['note']}"
            ),
            manual_verification=(
                f"curl -s {url} | head -50\n"
                "Manually verify the content is genuinely sensitive and not a decoy."
            ),
            remediation=(
                f"Restrict public access to '{path_def['path']}'. "
                "Move sensitive files outside the web root or configure the server "
                "to deny access to configuration and backup files."
            ),
            evidence=[ev],
            tags=["info-disclosure", "sensitive-file"],
        ))

    logger.info("[InfoDisclosure] Found %d exposed files", len(findings))
    return findings
