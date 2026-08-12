"""Express.js-specific endpoint discovery."""
from __future__ import annotations
import logging
from urllib.parse import urljoin
from scopehunter.core.evidence import EndpointInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

_EXPRESS_ENDPOINTS = [
    {"path": "/api/", "note": "API root", "source": "express-api"},
    {"path": "/api/v1/", "note": "API v1", "source": "express-api"},
    {"path": "/api/health", "note": "Health check", "source": "express-api"},
    {"path": "/api/status", "note": "Status endpoint", "source": "express-api"},
    {"path": "/api/docs", "note": "API documentation", "source": "express-api"},
    {"path": "/api-docs", "note": "Swagger/OpenAPI docs", "source": "express-api"},
    {"path": "/swagger.json", "note": "Swagger JSON spec", "source": "express-api"},
    {"path": "/openapi.json", "note": "OpenAPI spec", "source": "express-api"},
    {"path": "/.env", "note": "Environment file", "source": "express-sensitive"},
    {"path": "/package.json", "note": "Package.json (info disclosure)", "source": "express-sensitive"},
    {"path": "/api/users", "note": "Users API", "source": "express-api"},
    {"path": "/api/auth/login", "note": "Auth login", "source": "express-auth"},
    {"path": "/api/auth/register", "note": "Auth register", "source": "express-auth"},
    {"path": "/api/auth/logout", "note": "Auth logout", "source": "express-auth"},
    {"path": "/api/auth/refresh", "note": "Token refresh", "source": "express-auth"},
]

async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    endpoints = []
    base = target.rstrip("/")
    for ep_def in _EXPRESS_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))
        try:
            ev = await client.get(url)
            endpoints.append(EndpointInfo(
                url=url, method="GET", source=ep_def["source"],
                status_code=ev.status_code, response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="Express.js", confidence=0.8, notes=ep_def["note"],
            ))
        except Exception as e:
            logger.debug("Express probe %s: %s", url, e)
    logger.info("[Express.js] Discovered %d specific endpoints", len(endpoints))
    return endpoints
