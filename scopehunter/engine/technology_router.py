"""
technology_router.py — Routes scan context to technology-specific modules.

After fingerprinting, the router selects the most relevant technology
module and enriches the endpoint list with framework-specific paths.
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

from scopehunter.core.evidence import EndpointInfo, TechDetection

if TYPE_CHECKING:
    from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

# Maps technology name → module in scopehunter.technologies
_TECH_MODULE_MAP: dict[str, str] = {
    "WordPress": "scopehunter.technologies.wordpress",
    "WooCommerce": "scopehunter.technologies.wordpress",  # bundled with WP module
    "Laravel": "scopehunter.technologies.laravel",
    "Django": "scopehunter.technologies.django",
    "Express.js": "scopehunter.technologies.express",
    "Next.js": "scopehunter.technologies.nextjs",
}

# Minimum confidence to use a specific technology module
_TECH_CONFIDENCE_THRESHOLD = 0.5


class TechnologyRouter:
    """
    Routes the scan to appropriate technology-specific endpoint discovery.

    Each technology module exposes:
        async def get_specific_endpoints(client, target) -> list[EndpointInfo]
    """

    def __init__(self, client: "HttpClient") -> None:
        self.client = client

    async def enrich_endpoints(
        self,
        target: str,
        detections: list[TechDetection],
        technology_hint: str | None = None,
    ) -> list[EndpointInfo]:
        """
        Load technology-specific endpoint patterns and probe them.

        Returns additional endpoints not found by generic crawling.
        """
        additional: list[EndpointInfo] = []

        # Determine which tech modules to activate
        active_modules: set[str] = set()

        if technology_hint and technology_hint != "auto":
            mapped = _TECH_MODULE_MAP.get(technology_hint)
            if mapped:
                active_modules.add(mapped)

        for detection in detections:
            if detection.confidence >= _TECH_CONFIDENCE_THRESHOLD:
                mapped = _TECH_MODULE_MAP.get(detection.technology)
                if mapped:
                    active_modules.add(mapped)

        # If nothing detected with sufficient confidence, use generic
        if not active_modules:
            active_modules.add("scopehunter.technologies.generic")

        # Always include generic
        active_modules.add("scopehunter.technologies.generic")

        for module_path in active_modules:
            try:
                mod = importlib.import_module(module_path)
                if hasattr(mod, "get_specific_endpoints"):
                    logger.info("[Router] Running technology module: %s", module_path)
                    endpoints = await mod.get_specific_endpoints(self.client, target)
                    additional.extend(endpoints)
            except Exception as e:
                logger.warning("[Router] Module '%s' failed: %s", module_path, e)

        return additional

    @staticmethod
    def select_primary_technology(detections: list[TechDetection]) -> str | None:
        """Return the name of the highest-confidence detected technology."""
        frameworks = {"WordPress", "WooCommerce", "Laravel", "Django", "Express.js", "Next.js"}
        for d in sorted(detections, key=lambda x: x.confidence, reverse=True):
            if d.technology in frameworks and d.confidence >= _TECH_CONFIDENCE_THRESHOLD:
                return d.technology
        return None
