"""Laravel-specific endpoint discovery."""
from __future__ import annotations
import logging
from urllib.parse import urljoin
from scopehunter.core.evidence import EndpointInfo, ParameterInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

_LARAVEL_ENDPOINTS = [
    {"path": "/api/user", "note": "Sanctum authenticated user", "source": "laravel-api"},
    {"path": "/api/", "note": "API root", "source": "laravel-api"},
    {"path": "/_ignition/health-check", "note": "Ignition health (debug indicator)", "source": "laravel-debug"},
    {"path": "/_ignition/execute-solution", "note": "Ignition execute (if debug ON = critical)", "source": "laravel-debug"},
    {"path": "/storage/logs/laravel.log", "note": "Laravel log file (sensitive)", "source": "laravel-sensitive"},
    {"path": "/.env", "note": "Environment configuration file", "source": "laravel-sensitive"},
    {"path": "/.env.backup", "note": "Env backup file", "source": "laravel-sensitive"},
    {"path": "/api/docs", "note": "API documentation", "source": "laravel-api"},
    {"path": "/telescope", "note": "Laravel Telescope debug tool", "source": "laravel-debug"},
    {"path": "/telescope/requests", "note": "Telescope requests log", "source": "laravel-debug"},
    {"path": "/horizon", "note": "Laravel Horizon queue dashboard", "source": "laravel-debug"},
    {"path": "/api/sanctum/csrf-cookie", "note": "Sanctum CSRF cookie endpoint", "source": "laravel-auth"},
    {"path": "/login", "note": "Login page", "source": "laravel-auth"},
    {"path": "/register", "note": "Registration endpoint", "source": "laravel-auth"},
    {"path": "/password/reset", "note": "Password reset", "source": "laravel-auth"},
    {"path": "/oauth/token", "note": "Passport OAuth token endpoint", "source": "laravel-auth"},
    {"path": "/api/v1/", "note": "API v1 root", "source": "laravel-api"},
    {"path": "/api/v2/", "note": "API v2 root", "source": "laravel-api"},
]

async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    endpoints = []
    base = target.rstrip("/")
    for ep_def in _LARAVEL_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))
        try:
            ev = await client.get(url)
            endpoints.append(EndpointInfo(
                url=url, method="GET", source=ep_def["source"],
                status_code=ev.status_code, response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="Laravel", confidence=0.85, notes=ep_def["note"],
            ))
        except Exception as e:
            logger.debug("Laravel probe failed %s: %s", url, e)
    logger.info("[Laravel] Discovered %d specific endpoints", len(endpoints))
    return endpoints
