"""
orchestrator.py — Main scan coordinator.

Full pipeline:
    Target
      ↓ Scope Validation
      ↓ Fingerprint
      ↓ Technology Router
      ↓ Endpoint Discovery (crawl + technology-specific)
      ↓ Check Selection
      ↓ Safe Checks
      ↓ Evidence Correlation
      ↓ Finding
      ↓ Report
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable

from scopehunter.core.crawler import Crawler
from scopehunter.core.evidence import EndpointInfo, Finding, SessionProfile, TechDetection
from scopehunter.core.fingerprint import FingerprintEngine
from scopehunter.core.http import HttpClient
from scopehunter.core.rate_limit import RateLimiter
from scopehunter.core.scope import ScopeManager
from scopehunter.engine.check_runner import CheckContext, CheckRunner
from scopehunter.engine.finding_manager import FindingManager
from scopehunter.engine.technology_router import TechnologyRouter

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a single scan run."""

    target: str
    allowed_scope: list[str] = field(default_factory=list)
    technology_hint: str | None = None       # e.g. "WordPress", "auto"
    scan_profile: str = "full"               # "recon", "endpoint", "access_control", etc.
    sessions: list[SessionProfile] = field(default_factory=list)
    rate_limit: float = 5.0                  # requests per second
    timeout: float = 15.0
    max_depth: int = 3
    max_endpoints: int = 200
    min_confidence: float = 0.4
    verify_ssl: bool = True
    proxy: str | None = None
    custom_checks_dir: str | None = None


@dataclass
class ScanResult:
    """Result of a complete scan run."""

    target: str
    detections: list[TechDetection]
    endpoints: list[EndpointInfo]
    findings: list[Finding]
    scan_config: ScanConfig
    applicable_cves: list[dict]
    stats: dict


# Progress callback type: (stage, message, percent)
ProgressCallback = Callable[[str, str, float], None]


class Orchestrator:
    """
    Main scan coordinator. Runs the full pipeline from target to findings.

    Usage:
        config = ScanConfig(target="https://example.com")
        orch = Orchestrator(config, on_progress=my_callback)
        result = await orch.run()
    """

    def __init__(
        self,
        config: ScanConfig,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.config = config
        self._on_progress = on_progress or self._default_progress

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        cfg = self.config

        # ---------------------------------------------------------------
        # Stage 1: Setup core components
        # ---------------------------------------------------------------
        self._progress("setup", "Initializing scope and HTTP client...", 0.0)

        scope = ScopeManager(
            target=cfg.target,
            allowed_scope=cfg.allowed_scope,
        )
        rate_limiter = RateLimiter(requests_per_second=cfg.rate_limit)
        finding_manager = FindingManager(min_confidence=cfg.min_confidence)

        async with HttpClient(
            scope=scope,
            rate_limiter=rate_limiter,
            timeout=cfg.timeout,
            verify_ssl=cfg.verify_ssl,
            proxy=cfg.proxy,
        ) as client:

            # -----------------------------------------------------------
            # Stage 2: Technology fingerprinting
            # -----------------------------------------------------------
            self._progress("fingerprint", "Fingerprinting target technologies...", 0.1)
            fingerprinter = FingerprintEngine(client)
            detections = await fingerprinter.fingerprint(cfg.target)
            applicable_cves = fingerprinter.get_applicable_cves(detections)
            logger.info(
                "Fingerprinting complete: %d technologies detected, %d CVEs applicable",
                len(detections),
                len(applicable_cves),
            )

            # -----------------------------------------------------------
            # Stage 3: Technology routing + specific endpoint discovery
            # -----------------------------------------------------------
            self._progress("routing", "Loading technology-specific endpoint patterns...", 0.25)
            router = TechnologyRouter(client)
            tech_endpoints = await router.enrich_endpoints(
                cfg.target, detections, cfg.technology_hint
            )

            # -----------------------------------------------------------
            # Stage 4: Generic crawl
            # -----------------------------------------------------------
            self._progress("crawl", "Crawling for endpoints...", 0.35)
            crawler = Crawler(
                client=client,
                scope=scope,
                max_depth=cfg.max_depth,
                max_endpoints=cfg.max_endpoints,
            )
            crawled_endpoints = await crawler.crawl(cfg.target)

            # Merge, deduplicate by URL+method
            all_endpoints = self._merge_endpoints(crawled_endpoints, tech_endpoints)
            logger.info("Endpoint discovery complete: %d endpoints found", len(all_endpoints))

            # -----------------------------------------------------------
            # Stage 5: Run checks
            # -----------------------------------------------------------
            self._progress("checks", f"Running safety checks ({cfg.scan_profile})...", 0.55)
            from pathlib import Path
            runner = CheckRunner(
                custom_checks_dir=Path(cfg.custom_checks_dir) if cfg.custom_checks_dir else None
            )
            runner.load_checks(cfg.scan_profile)

            context = CheckContext(
                target=cfg.target,
                client=client,
                endpoints=all_endpoints,
                detections=detections,
                sessions=cfg.sessions,
                finding_manager=finding_manager,
                technology_hint=cfg.technology_hint,
                scan_profile=cfg.scan_profile,
            )
            total_new = await runner.run_all(context)
            logger.info("Checks complete: %d new findings", total_new)

            # -----------------------------------------------------------
            # Stage 6: Finalize
            # -----------------------------------------------------------
            self._progress("done", "Scan complete. Generating report...", 1.0)

            all_findings = finding_manager.all_findings()
            stats = {
                "endpoints_discovered": len(all_endpoints),
                "technologies_detected": len(detections),
                "findings_total": len(all_findings),
                "findings_by_severity": finding_manager.summary(),
                "applicable_cves": len(applicable_cves),
            }

            return ScanResult(
                target=cfg.target,
                detections=detections,
                endpoints=all_endpoints,
                findings=all_findings,
                scan_config=cfg,
                applicable_cves=applicable_cves,
                stats=stats,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_endpoints(
        *endpoint_lists: list[EndpointInfo],
    ) -> list[EndpointInfo]:
        seen: dict[str, EndpointInfo] = {}
        for lst in endpoint_lists:
            for ep in lst:
                key = f"{ep.method}:{ep.url}"
                if key not in seen:
                    seen[key] = ep
        return list(seen.values())

    def _progress(self, stage: str, message: str, percent: float) -> None:
        try:
            self._on_progress(stage, message, percent)
        except Exception:
            pass

    @staticmethod
    def _default_progress(stage: str, message: str, percent: float) -> None:
        logger.info("[%.0f%%] %s: %s", percent * 100, stage.upper(), message)
