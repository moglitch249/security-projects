"""
test_evidence.py — Unit tests for evidence data models.
"""

import pytest
from scopehunter.core.evidence import (
    Confidence,
    Finding,
    HttpEvidence,
    ParameterInfo,
    Severity,
    SessionProfile,
    TechDetection,
    VulnClass,
)


def _make_evidence(**kwargs) -> HttpEvidence:
    defaults = dict(
        url="https://example.com/api",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body_snippet='{"id": 1, "user_id": 42}',
        response_size=100,
        elapsed_ms=50.0,
    )
    defaults.update(kwargs)
    return HttpEvidence(**defaults)


def test_confidence_from_score_high():
    assert Confidence.from_score(0.9) == Confidence.HIGH


def test_confidence_from_score_medium():
    assert Confidence.from_score(0.6) == Confidence.MEDIUM


def test_confidence_from_score_low():
    assert Confidence.from_score(0.3) == Confidence.LOW


def test_session_profile_bearer_token():
    s = SessionProfile(name="admin", bearer_token="mytoken")
    hdrs = s.to_httpx_headers()
    assert hdrs["Authorization"] == "Bearer mytoken"


def test_session_profile_cookies():
    s = SessionProfile(name="user", cookies={"session": "abc123"})
    assert s.cookies["session"] == "abc123"


def test_finding_to_dict():
    ev = _make_evidence()
    f = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        confidence_score=0.85,
        vuln_class=VulnClass.IDOR,
        technology="WordPress",
        endpoint="https://example.com/api/orders/1",
        method="GET",
        parameter="id=1",
        description="Test description",
        why_it_matters="It matters.",
        manual_verification="Verify manually.",
        remediation="Fix it.",
        evidence=[ev],
    )
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["confidence"] == "high"
    assert d["confidence_score"] == 0.85
    assert len(d["evidence"]) == 1


def test_parameter_info_object_identifier():
    p = ParameterInfo(name="user_id", location="query", is_object_identifier=True)
    assert p.is_object_identifier is True


def test_tech_detection_confidence():
    d = TechDetection(technology="WordPress", confidence=0.96, version="6.4.1", evidence=["body match"])
    assert d.confidence == 0.96
    assert d.version == "6.4.1"
