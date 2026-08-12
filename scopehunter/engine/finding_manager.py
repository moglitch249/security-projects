"""
finding_manager.py — Deduplication, scoring, and storage of findings.

Prevents duplicate findings and groups related evidence together.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from scopehunter.core.evidence import Finding, Severity


class FindingManager:
    """
    Manages findings across the scan lifecycle.

    Responsibilities:
    - Deduplication via fingerprint hash
    - Grouping by severity
    - Confidence-based filtering
    """

    def __init__(self, min_confidence: float = 0.4) -> None:
        self.min_confidence = min_confidence
        self._findings: dict[str, Finding] = {}  # hash → Finding

    def add(self, finding: Finding) -> bool:
        """
        Add a finding. Returns True if it was new, False if duplicate.

        Deduplication key: vuln_class + endpoint + parameter
        """
        if finding.confidence_score < self.min_confidence:
            return False

        key = self._fingerprint(finding)
        if key in self._findings:
            # Merge evidence from duplicate
            existing = self._findings[key]
            existing.evidence.extend(finding.evidence)
            # Boost confidence slightly if we see it again
            existing.confidence_score = min(
                existing.confidence_score + 0.05, 1.0
            )
            return False

        self._findings[key] = finding
        return True

    def all_findings(self) -> list[Finding]:
        """Return all findings sorted by severity and confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(
            self._findings.values(),
            key=lambda f: (severity_order[f.severity], -f.confidence_score),
        )

    def by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in self.all_findings():
            groups[f.severity.value].append(f)
        return dict(groups)

    def summary(self) -> dict[str, int]:
        """Return count per severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self._findings.values():
            counts[f.severity.value] += 1
        return counts

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        raw = f"{finding.vuln_class.value}:{finding.endpoint}:{finding.parameter}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
