"""
json_report.py — JSON report generator.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from scopehunter.engine.orchestrator import ScanResult


def generate(result: ScanResult, output_path: Path) -> None:
    """Write a structured JSON report to output_path."""
    report = {
        "scopehunter_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.target,
        "scan_profile": result.scan_config.scan_profile,
        "statistics": result.stats,
        "technology_detections": [
            {
                "technology": d.technology,
                "confidence": d.confidence,
                "version": d.version,
                "evidence": d.evidence,
            }
            for d in result.detections
        ],
        "applicable_cves": result.applicable_cves,
        "endpoints": [
            {
                "url": ep.url,
                "method": ep.method,
                "source": ep.source,
                "status_code": ep.status_code,
                "response_size": ep.response_size,
                "technology": ep.technology,
                "has_object_ids": ep.has_object_identifiers,
                "parameters": [
                    {
                        "name": p.name,
                        "location": p.location,
                        "is_object_identifier": p.is_object_identifier,
                    }
                    for p in ep.parameters
                ],
            }
            for ep in result.endpoints
        ],
        "findings": [f.to_dict() for f in result.findings],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
