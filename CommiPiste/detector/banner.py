"""Auto-detect which software a target runs, by banner/path.

Checks each candidate project's banner spec against the target: response headers and body of the
landing page, plus dedicated marker paths (e.g. Nextcloud's /status.php). Returns the matching
project names, best-effort and order-preserving.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from ..models import Project


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    # Follow redirects here (unlike asset fetches): a landing page legitimately redirects
    # (http->https, / -> /login), and we only read it for detection markers.
    try:
        return await client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return None


async def detect_software(
    client: httpx.AsyncClient,
    url: str,
    candidates: list[Project],
    *,
    path: str | None = None,
) -> list[str]:
    """Return names of candidate projects whose banner matches the target."""
    base = url if url.endswith("/") else url + "/"
    if path:
        base = urljoin(base, path.lstrip("/"))
        base = base if base.endswith("/") else base + "/"

    landing = await _get(client, base)
    landing_body = landing.text if landing is not None else ""
    landing_headers = {k.lower(): v for k, v in (landing.headers.items() if landing else [])}

    matched: list[str] = []
    for project in candidates:
        if await _matches(client, base, project, landing_body, landing_headers):
            matched.append(project.name)
    return matched


async def _matches(
    client: httpx.AsyncClient,
    base: str,
    project: Project,
    landing_body: str,
    landing_headers: dict[str, str],
) -> bool:
    spec = project.banners

    # Strongest signal first: a dedicated marker endpoint returning the expected content.
    for probe in spec.paths:
        resp = await _get(client, urljoin(base, probe.path.lstrip("/")))
        if resp is None or resp.status_code != 200:
            continue
        if probe.match is None or re.search(probe.match, resp.text):
            return True

    # Header value must match a pattern — header presence alone is not a signal.
    for name, pattern in spec.headers.items():
        value = landing_headers.get(name.lower())
        if value and re.search(pattern, value):
            return True

    for pattern in spec.body_regex:
        if landing_body and re.search(pattern, landing_body):
            return True

    return False
