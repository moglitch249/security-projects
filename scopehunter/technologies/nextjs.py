"""Next.js-specific endpoint discovery."""
from __future__ import annotations
import logging
from urllib.parse import urljoin
from scopehunter.core.evidence import EndpointInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

_NEXTJS_ENDPOINTS = [
    {"path": "/api/", "note": "Next.js API routes root", "source": "nextjs-api"},
    {"path": "/api/health", "note": "Health check", "source": "nextjs-api"},
    {"path": "/api/auth/session", "note": "NextAuth session", "source": "nextjs-auth"},
    {"path": "/api/auth/signin", "note": "NextAuth sign-in", "source": "nextjs-auth"},
    {"path": "/api/auth/signout", "note": "NextAuth sign-out", "source": "nextjs-auth"},
    {"path": "/api/auth/providers", "note": "NextAuth providers list", "source": "nextjs-auth"},
    {"path": "/api/auth/csrf", "note": "NextAuth CSRF token", "source": "nextjs-auth"},
    {"path": "/_next/static/", "note": "Static assets", "source": "nextjs-static"},
    {"path": "/_next/data/", "note": "Server-side props data", "source": "nextjs-data"},
    {"path": "/api/trpc/", "note": "tRPC endpoint (if used)", "source": "nextjs-api"},
    {"path": "/.env.local", "note": "Local env file (should be private)", "source": "nextjs-sensitive"},
    {"path": "/api/graphql", "note": "GraphQL endpoint", "source": "nextjs-api"},
    {"path": "/api/users", "note": "Users API", "source": "nextjs-api"},
    {"path": "/api/me", "note": "Current user API", "source": "nextjs-api"},
]

async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    endpoints = []
    base = target.rstrip("/")
    for ep_def in _NEXTJS_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))
        try:
            ev = await client.get(url)
            endpoints.append(EndpointInfo(
                url=url, method="GET", source=ep_def["source"],
                status_code=ev.status_code, response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="Next.js", confidence=0.85, notes=ep_def["note"],
            ))
        except Exception as e:
            logger.debug("Next.js probe %s: %s", url, e)
    logger.info("[Next.js] Discovered %d specific endpoints", len(endpoints))
    return endpoints
