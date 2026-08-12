"""
test_scope.py — Unit tests for the ScopeManager.
"""

import pytest
from scopehunter.core.scope import ScopeManager, ScopeViolation


def test_in_scope_exact_domain():
    scope = ScopeManager(target="https://example.com")
    scope.check("https://example.com/api/users")  # should not raise


def test_in_scope_subdomain():
    scope = ScopeManager(target="https://example.com", allow_subdomains=True)
    scope.check("https://api.example.com/v1/users")  # should not raise


def test_out_of_scope_different_domain():
    scope = ScopeManager(target="https://example.com")
    with pytest.raises(ScopeViolation):
        scope.check("https://evil.com/steal")


def test_blocked_http_method_delete():
    scope = ScopeManager(target="https://example.com")
    with pytest.raises(ScopeViolation):
        scope.check("https://example.com/api/users/1", method="DELETE")


def test_blocked_http_method_patch():
    scope = ScopeManager(target="https://example.com")
    with pytest.raises(ScopeViolation):
        scope.check("https://example.com/api/users/1", method="PATCH")


def test_additional_scope_rule():
    scope = ScopeManager(
        target="https://example.com",
        allowed_scope=["staging.example.com"]
    )
    scope.check("https://staging.example.com/api")  # should not raise


def test_filter_urls():
    scope = ScopeManager(target="https://example.com")
    urls = [
        "https://example.com/page1",
        "https://evil.com/steal",
        "https://example.com/api",
    ]
    filtered = scope.filter_urls(urls)
    assert len(filtered) == 2
    assert all("example.com" in u for u in filtered)


def test_is_in_scope_returns_bool():
    scope = ScopeManager(target="https://example.com")
    assert scope.is_in_scope("https://example.com/api") is True
    assert scope.is_in_scope("https://evil.com") is False


def test_unsupported_scheme_blocked():
    scope = ScopeManager(target="https://example.com")
    with pytest.raises(ScopeViolation):
        scope.check("ftp://example.com/file")
