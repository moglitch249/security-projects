"""
check_runner.py — Async check execution engine with importlib plugin loading.

Loads check modules from scopehunter/checks/ and custom_checks/ directories.
Each check module must expose:
    - CHECK_NAME: str
    - CHECK_DESCRIPTION: str
    - async def run(context: CheckContext) -> list[Finding]
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from scopehunter.core.evidence import EndpointInfo, Finding, SessionProfile, TechDetection
from scopehunter.core.http import HttpClient
from scopehunter.engine.finding_manager import FindingManager

logger = logging.getLogger(__name__)


class CheckModule(Protocol):
    """Protocol defining the interface all check modules must implement."""

    CHECK_NAME: str
    CHECK_DESCRIPTION: str

    async def run(self, context: "CheckContext") -> list[Finding]:
        ...


@dataclass
class CheckContext:
    """Context object passed to every check module."""

    target: str
    client: HttpClient
    endpoints: list[EndpointInfo]
    detections: list[TechDetection]
    sessions: list[SessionProfile]
    finding_manager: FindingManager
    technology_hint: str | None = None
    scan_profile: str = "full"
    extra: dict = field(default_factory=dict)

    def get_session(self, name: str) -> SessionProfile | None:
        return next((s for s in self.sessions if s.name == name), None)

    def get_sessions_by_role(self, role: str) -> list[SessionProfile]:
        return [s for s in self.sessions if role.lower() in s.name.lower()]


class CheckRunner:
    """
    Discovers and executes check modules.

    Built-in checks: scopehunter/checks/**/*.py
    Custom checks:   custom_checks/*.py  (importlib plugin architecture)
    """

    def __init__(self, custom_checks_dir: Path | None = None) -> None:
        self._custom_checks_dir = custom_checks_dir
        self._checks: list[CheckModule] = []

    def load_checks(self, scan_profile: str = "full") -> None:
        """Load all applicable check modules."""
        self._checks.clear()
        self._load_builtin_checks(scan_profile)
        if self._custom_checks_dir and self._custom_checks_dir.exists():
            self._load_custom_checks(self._custom_checks_dir)
        logger.info("Loaded %d check modules for profile '%s'", len(self._checks), scan_profile)

    async def run_all(self, context: CheckContext) -> int:
        """
        Run all loaded checks and add findings to context.finding_manager.

        Returns total count of new findings added.
        """
        total_new = 0
        for check in self._checks:
            logger.info("[CheckRunner] Running: %s", check.CHECK_NAME)
            try:
                findings = await check.run(context)
                for f in findings:
                    if context.finding_manager.add(f):
                        total_new += 1
            except Exception as e:
                logger.error("[CheckRunner] Check '%s' failed: %s", check.CHECK_NAME, e)
        return total_new

    @property
    def loaded_checks(self) -> list[str]:
        return [c.CHECK_NAME for c in self._checks]

    # ------------------------------------------------------------------
    # Private loaders
    # ------------------------------------------------------------------

    def _load_builtin_checks(self, scan_profile: str) -> None:
        """Walk the built-in checks package and import each module."""
        checks_pkg_path = Path(__file__).parent.parent / "checks"
        self._walk_and_import(checks_pkg_path, "scopehunter.checks")

    def _walk_and_import(self, base_path: Path, pkg_prefix: str) -> None:
        """Recursively import all Python modules under base_path."""
        for path in sorted(base_path.rglob("*.py")):
            if path.name.startswith("_"):
                continue
            # Build dotted module name
            relative = path.relative_to(base_path.parent)
            module_name = pkg_prefix.rsplit(".", 1)[0] + "." + ".".join(
                relative.with_suffix("").parts
            )
            try:
                mod = importlib.import_module(module_name)
                if hasattr(mod, "CHECK_NAME") and hasattr(mod, "run"):
                    self._checks.append(mod)  # type: ignore[arg-type]
                    logger.debug("Loaded check: %s", mod.CHECK_NAME)
            except Exception as e:
                logger.warning("Failed to load check '%s': %s", module_name, e)

    def _load_custom_checks(self, directory: Path) -> None:
        """Load custom check plugins from an external directory."""
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(f"custom.{path.stem}", path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)  # type: ignore[union-attr]
                    if hasattr(mod, "CHECK_NAME") and hasattr(mod, "run"):
                        self._checks.append(mod)  # type: ignore[arg-type]
                        logger.info("Loaded custom check: %s", mod.CHECK_NAME)
                except Exception as e:
                    logger.warning("Failed to load custom check '%s': %s", path, e)
