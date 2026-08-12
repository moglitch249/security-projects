"""
fingerprint.py — Passive technology fingerprinting engine.

Identifies technologies using multiple signal types:
    - HTTP response headers
    - Set-Cookie headers / cookie names
    - HTML body patterns
    - Path probing (safe GET requests)
    - Version extraction via regex

Assigns confidence scores per technology based on matched signals.
Does NOT make assumptions from a single signal.
"""

from __future__ import annotations

import importlib.resources
import json
import logging
import re
from urllib.parse import urljoin

from scopehunter.core.evidence import HttpEvidence, TechDetection
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

# Minimum confidence to include a technology in results
_MIN_CONFIDENCE_THRESHOLD = 0.3


def _load_signatures() -> dict:
    ref = importlib.resources.files("scopehunter.config") / "signatures.json"
    with ref.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_cves() -> list[dict]:
    ref = importlib.resources.files("scopehunter.config") / "cve_mappings.json"
    with ref.open("r", encoding="utf-8") as f:
        return json.load(f).get("cves", [])


class FingerprintEngine:
    """
    Passive fingerprinting engine.

    Usage:
        engine = FingerprintEngine(client)
        detections = await engine.fingerprint("https://target.com")
    """

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        self._sigs = _load_signatures()
        self._cves = _load_cves()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fingerprint(self, target: str) -> list[TechDetection]:
        """
        Run passive fingerprinting against the target.

        Returns:
            List of TechDetection ordered by confidence descending.
        """
        # Fetch root page
        try:
            root_evidence = await self.client.get(target)
        except Exception as e:
            logger.warning("Fingerprint: failed to fetch root page: %s", e)
            return []

        tech_scores: dict[str, dict] = {}

        technologies = self._sigs.get("technologies", {})
        for tech_name, tech_data in technologies.items():
            signals = tech_data.get("signals", [])
            matched_evidence: list[str] = []
            total_score = 0.0
            max_possible = sum(s["score"] for s in signals)

            for signal in signals:
                hit, desc = await self._evaluate_signal(signal, root_evidence, target)
                if hit:
                    total_score += signal["score"]
                    matched_evidence.append(desc)

            if max_possible > 0:
                confidence = min(total_score / max_possible, 1.0)
                # Normalize with weight
                weight = tech_data.get("weight", 1.0)
                normalized = min(confidence * weight * 1.2, 1.0)  # small boost

                if normalized >= _MIN_CONFIDENCE_THRESHOLD and matched_evidence:
                    tech_scores[tech_name] = {
                        "confidence": normalized,
                        "evidence": matched_evidence,
                    }

        # Extract versions
        detections: list[TechDetection] = []
        version_patterns = self._sigs.get("version_patterns", {})

        for tech_name, data in tech_scores.items():
            version = await self._extract_version(
                tech_name, root_evidence, target, version_patterns
            )
            detections.append(
                TechDetection(
                    technology=tech_name,
                    confidence=round(data["confidence"], 3),
                    version=version,
                    evidence=data["evidence"],
                )
            )

        detections.sort(key=lambda d: d.confidence, reverse=True)
        return detections

    def get_applicable_cves(
        self, detections: list[TechDetection]
    ) -> list[dict]:
        """
        Check detected technologies+versions against the CVE database.
        Returns only CVEs where the detected version falls in the affected range.
        Never used for exploitation — only flagged for manual review.
        """
        applicable: list[dict] = []
        tech_version_map = {d.technology: d.version for d in detections}

        for cve in self._cves:
            component = cve["component"]
            # Match component name against detected techs (substring match)
            matched_tech = next(
                (t for t in tech_version_map if component.lower() in t.lower()), None
            )
            if matched_tech is None:
                continue

            detected_version = tech_version_map.get(matched_tech)
            # If we can detect and compare the version:
            is_applicable = self._check_version_in_range(
                detected_version, cve["affected_versions"]
            )

            if is_applicable or detected_version is None:
                applicable.append(
                    {
                        **cve,
                        "detected_version": detected_version,
                        "version_confirmed": detected_version is not None and is_applicable,
                        "matched_tech": matched_tech,
                    }
                )

        return applicable

    # ------------------------------------------------------------------
    # Signal evaluation
    # ------------------------------------------------------------------

    async def _evaluate_signal(
        self, signal: dict, evidence: HttpEvidence, target: str
    ) -> tuple[bool, str]:
        """
        Evaluate a single fingerprint signal against an HTTP evidence snapshot.

        Returns (matched: bool, description: str)
        """
        sig_type = signal["type"]
        flags = re.IGNORECASE if signal.get("case_insensitive") else 0

        if sig_type == "header":
            header_name = signal["name"].lower()
            header_value = evidence.response_headers.get(header_name, "")
            pattern = signal.get("pattern", "")
            if re.search(pattern, header_value, flags):
                return True, f"Header '{header_name}' matches '{pattern}'"

        elif sig_type == "cookie":
            cookie_pattern = signal["name"]
            set_cookie = evidence.response_headers.get("set-cookie", "")
            if re.search(cookie_pattern, set_cookie, re.IGNORECASE):
                return True, f"Cookie matches pattern '{cookie_pattern}'"

        elif sig_type == "body":
            pattern = signal.get("pattern", "")
            if re.search(pattern, evidence.response_body_snippet, flags | re.DOTALL):
                return True, f"Body matches pattern '{pattern[:60]}'"

        elif sig_type == "path_exists":
            path = signal["path"]
            probe_url = urljoin(target, path)
            try:
                probe = await self.client.get(probe_url)
                if probe.status_code in (200, 301, 302, 403):
                    return True, f"Path '{path}' returned {probe.status_code}"
            except Exception:
                pass

        return False, ""

    # ------------------------------------------------------------------
    # Version extraction
    # ------------------------------------------------------------------

    async def _extract_version(
        self,
        tech: str,
        root_evidence: HttpEvidence,
        target: str,
        version_patterns: dict,
    ) -> str | None:
        """Try to extract a version string for a technology."""
        patterns = version_patterns.get(tech, [])
        for pat in patterns:
            pat_type = pat["type"]
            regex = re.compile(pat["pattern"], re.IGNORECASE)
            group = pat.get("group", 1)

            if pat_type == "body":
                m = regex.search(root_evidence.response_body_snippet)
                if m:
                    try:
                        return m.group(group)
                    except IndexError:
                        pass

            elif pat_type == "header":
                header_val = root_evidence.response_headers.get(pat["name"].lower(), "")
                m = regex.search(header_val)
                if m:
                    try:
                        return m.group(group)
                    except IndexError:
                        pass

            elif pat_type == "path_response":
                probe_url = urljoin(target, pat["path"])
                try:
                    probe = await self.client.get(probe_url)
                    m = regex.search(probe.response_body_snippet)
                    if m:
                        try:
                            return m.group(group)
                        except IndexError:
                            pass
                except Exception:
                    pass

        return None

    # ------------------------------------------------------------------
    # Version comparison (simple semver-like)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_version_in_range(detected: str | None, affected: str) -> bool:
        """
        Very simple version range check.
        Supports: "< X.Y.Z", "<= X.Y.Z", "> X.Y.Z", ">= X.Y.Z"
        """
        if not detected:
            return False

        def parse(v: str) -> tuple[int, ...]:
            try:
                return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
            except Exception:
                return (0,)

        detected_t = parse(detected)
        m = re.match(r"([<>]=?)\s*([\d.]+)", affected.strip())
        if not m:
            return False

        op, ver_str = m.group(1), m.group(2)
        ver_t = parse(ver_str)

        if op == "<":
            return detected_t < ver_t
        elif op == "<=":
            return detected_t <= ver_t
        elif op == ">":
            return detected_t > ver_t
        elif op == ">=":
            return detected_t >= ver_t
        return False
