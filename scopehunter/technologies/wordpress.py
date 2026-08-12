"""
wordpress.py — WordPress & WooCommerce specific endpoint discovery.

Probes well-known public WordPress paths to build the attack surface map.
All requests are safe GET requests only.
"""

from __future__ import annotations

import logging
from urllib.parse import urljoin

from scopehunter.core.evidence import EndpointInfo, ParameterInfo
from scopehunter.core.http import HttpClient

logger = logging.getLogger(__name__)

# Known public WordPress endpoints and their metadata
_WP_ENDPOINTS: list[dict] = [
    # REST API
    {"path": "/wp-json/", "note": "REST API root", "source": "wp-rest"},
    {"path": "/wp-json/wp/v2/", "note": "REST API v2 root", "source": "wp-rest"},
    {"path": "/wp-json/wp/v2/users", "note": "User enumeration endpoint", "source": "wp-rest",
     "params": [{"name": "per_page", "loc": "query"}, {"name": "page", "loc": "query"}]},
    {"path": "/wp-json/wp/v2/posts", "note": "Posts endpoint", "source": "wp-rest",
     "params": [{"name": "id", "loc": "query", "is_id": True}]},
    {"path": "/wp-json/wp/v2/pages", "note": "Pages endpoint", "source": "wp-rest"},
    {"path": "/wp-json/wp/v2/categories", "note": "Categories", "source": "wp-rest"},
    {"path": "/wp-json/wp/v2/media", "note": "Media library", "source": "wp-rest"},
    {"path": "/wp-json/wp/v2/comments", "note": "Comments", "source": "wp-rest"},
    # WooCommerce REST API (public endpoints)
    {"path": "/wp-json/wc/v3/", "note": "WooCommerce REST root", "source": "woocommerce"},
    {"path": "/wp-json/wc/v3/products", "note": "WC products", "source": "woocommerce",
     "params": [{"name": "id", "loc": "query", "is_id": True}]},
    {"path": "/wp-json/wc/v3/products/categories", "note": "WC product categories", "source": "woocommerce"},
    {"path": "/wp-json/wc/store/v1/", "note": "WC Store API root", "source": "woocommerce"},
    {"path": "/wp-json/wc/store/v1/cart", "note": "WC cart", "source": "woocommerce"},
    {"path": "/wp-json/wc/store/v1/products", "note": "WC store products", "source": "woocommerce"},
    # XML-RPC
    {"path": "/xmlrpc.php", "note": "XML-RPC interface (legacy)", "source": "wp-xmlrpc"},
    # Public admin / login
    {"path": "/wp-login.php", "note": "WordPress login page", "source": "wp-core"},
    {"path": "/wp-admin/", "note": "Admin dashboard (auth required)", "source": "wp-core"},
    {"path": "/wp-admin/admin-ajax.php", "note": "AJAX endpoint", "source": "wp-core"},
    # Common feeds
    {"path": "/feed/", "note": "RSS feed (version leak)", "source": "wp-core"},
    {"path": "/wp-sitemap.xml", "note": "WordPress sitemap", "source": "wp-core"},
    # Common sensitive files
    {"path": "/wp-config.php.bak", "note": "WP config backup (if exposed)", "source": "wp-sensitive"},
    {"path": "/wp-config.php~", "note": "WP config temp file", "source": "wp-sensitive"},
    {"path": "/.env", "note": "Environment file", "source": "wp-sensitive"},
    {"path": "/readme.html", "note": "WordPress readme (version info)", "source": "wp-info"},
    {"path": "/license.txt", "note": "WordPress license (version info)", "source": "wp-info"},
    # oEmbed
    {"path": "/wp-json/oembed/1.0/", "note": "oEmbed endpoint", "source": "wp-rest"},
    {"path": "/?rest_route=/wp/v2/users", "note": "REST users (alt route)", "source": "wp-rest"},
]


async def get_specific_endpoints(client: HttpClient, target: str) -> list[EndpointInfo]:
    """
    Probe known WordPress endpoint patterns and return discovered ones.
    Only records endpoints that respond (any status code counts as found).
    """
    endpoints: list[EndpointInfo] = []
    base = target.rstrip("/")

    for ep_def in _WP_ENDPOINTS:
        url = urljoin(base + "/", ep_def["path"].lstrip("/"))

        # Scope check is handled inside client.get()
        try:
            ev = await client.get(url)
        except Exception as e:
            logger.debug("WP probe failed %s: %s", url, e)
            continue

        params: list[ParameterInfo] = []
        for p in ep_def.get("params", []):
            params.append(
                ParameterInfo(
                    name=p["name"],
                    location=p["loc"],
                    is_object_identifier=p.get("is_id", False),
                )
            )

        endpoints.append(
            EndpointInfo(
                url=url,
                method="GET",
                parameters=params,
                source=ep_def["source"],
                status_code=ev.status_code,
                response_size=ev.response_size,
                content_type=ev.response_headers.get("content-type"),
                technology="WordPress",
                confidence=0.9,
                notes=ep_def["note"],
            )
        )

    logger.info("[WordPress] Discovered %d specific endpoints", len(endpoints))
    return endpoints
