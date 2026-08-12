"""Generic web application endpoint discovery (technology-agnostic)."""
from __future__ import annotations
import logging
from urllib.parse import urljoin
from scopehunter.core.evidence import EndpointInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

_GENERIC_ENDPOINTS = [
    # API patterns
    {"path": "/api/", "note": "API root", "source": "generic"},
    {"path": "/api/v1/", "note": "API v1", "source": "generic"},
    {"path": "/api/v2/", "note": "API v2", "source": "generic"},
    {"path": "/api/health", "note": "Health check", "source": "generic"},
    {"path": "/api/status", "note": "Status endpoint", "source": "generic"},
    {"path": "/graphql", "note": "GraphQL endpoint", "source": "generic"},
    # Documentation
    {"path": "/swagger.json", "note": "Swagger spec", "source": "generic-docs"},
    {"path": "/openapi.json", "note": "OpenAPI spec", "source": "generic-docs"},
    {"path": "/api-docs", "note": "API docs", "source": "generic-docs"},
    {"path": "/api/docs", "note": "API docs", "source": "generic-docs"},
    {"path": "/docs", "note": "Documentation", "source": "generic-docs"},
    # Sensitive files
    {"path": "/.env", "note": "Environment file", "source": "generic-sensitive"},
    {"path": "/.git/config", "note": "Git config (exposed repo)", "source": "generic-sensitive"},
    {"path": "/robots.txt", "note": "Robots.txt", "source": "generic-info"},
    {"path": "/sitemap.xml", "note": "Sitemap", "source": "generic-info"},
    {"path": "/humans.txt", "note": "Humans.txt (may expose info)", "source": "generic-info"},
    {"path": "/security.txt", "note": "Security disclosure policy", "source": "generic-info"},
    {"path": "/.well-known/security.txt", "note": "Security.txt (standard path)", "source": "generic-info"},
    # Auth endpoints
    {"path": "/login", "note": "Login", "source": "generic-auth"},
    {"path": "/signin", "note": "Sign-in", "source": "generic-auth"},
    {"path": "/register", "note": "Registration", "source": "generic-auth"},
    {"path": "/signup", "note": "Sign-up", "source": "generic-auth"},
    {"path": "/logout", "note": "Logout", "source": "generic-auth"},
    {"path": "/forgot-password", "note": "Password reset", "source": "generic-auth"},
    # Admin
    {"path": "/admin", "note": "Admin interface", "source": "generic-admin"},
    {"path": "/dashboard", "note": "Dashboard", "source": "generic-admin"},
    {"path": "/manage", "note": "Management interface", "source": "generic-admin"},
    # User resources
    {"path": "/api/users", "note": "Users resource", "source": "generic-api"},
    {"path": "/api/profile", "note": "User profile", "source": "generic-api"},
    {"path": "/api/me", "note": "Current user", "source": "generic-api"},
    {"path": "/api/account", "note": "Account endpoint", "source": "generic-api"},
]

async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    endpoints = []
    base = target.rstrip("/")
    for ep_def in _GENERIC_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))
        try:
            ev = await client.get(url)
            endpoints.append(EndpointInfo(
                url=url, method="GET", source=ep_def["source"],
                status_code=ev.status_code, response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="Generic", confidence=0.6, notes=ep_def["note"],
            ))
        except Exception as e:
            logger.debug("Generic probe %s: %s", url, e)
    logger.info("[Generic] Discovered %d specific endpoints", len(endpoints))
    return endpoints
