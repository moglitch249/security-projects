"""Django-specific endpoint discovery."""
from __future__ import annotations
import logging
from urllib.parse import urljoin
from scopehunter.core.evidence import EndpointInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

_DJANGO_ENDPOINTS = [
    {"path": "/admin/", "note": "Django admin interface", "source": "django-admin"},
    {"path": "/admin/login/", "note": "Django admin login", "source": "django-admin"},
    {"path": "/api/", "note": "API root", "source": "django-api"},
    {"path": "/api/v1/", "note": "API v1", "source": "django-api"},
    {"path": "/api/schema/", "note": "OpenAPI schema", "source": "django-api"},
    {"path": "/api/docs/", "note": "DRF browsable API docs", "source": "django-api"},
    {"path": "/api/redoc/", "note": "ReDoc API docs", "source": "django-api"},
    {"path": "/api/swagger/", "note": "Swagger API docs", "source": "django-api"},
    {"path": "/__debug__/", "note": "Django Debug Toolbar", "source": "django-debug"},
    {"path": "/media/", "note": "Media files directory", "source": "django-sensitive"},
    {"path": "/static/", "note": "Static files", "source": "django-static"},
    {"path": "/.env", "note": "Environment file", "source": "django-sensitive"},
    {"path": "/sitemap.xml", "note": "Sitemap", "source": "django-info"},
]

async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    endpoints = []
    base = target.rstrip("/")
    for ep_def in _DJANGO_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))
        try:
            ev = await client.get(url)
            endpoints.append(EndpointInfo(
                url=url, method="GET", source=ep_def["source"],
                status_code=ev.status_code, response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="Django", confidence=0.85, notes=ep_def["note"],
            ))
        except Exception as e:
            logger.debug("Django probe %s: %s", url, e)
    logger.info("[Django] Discovered %d specific endpoints", len(endpoints))
    return endpoints
