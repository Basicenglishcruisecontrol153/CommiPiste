"""Trigger checks of dependent projects in the same public folder.

A core project (e.g. WordPress) serves dependent projects from sub-paths of its web root —
WordPress plugins live at ``wp-content/plugins/<slug>/`` and their assets are reachable there. Each
dependent is fingerprinted as a standalone unit against its own signature DB, but fetched under its
``served_prefix`` relative to the parent's web root.

To avoid hammering a target with probes for plugins that aren't installed, each dependent is first
presence-checked cheaply (its ``readme.txt`` — shipped by every wordpress.org plugin) and only
fully scanned (and reported) if it's actually there.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from ..models import Finding, Project
from ..registry import Registry
from ..storage import Storage


def _join(*parts: str) -> str:
    return "/".join(p.strip("/") for p in parts if p)


async def _present(client, url: str, base_path: str, markers: list[str]) -> bool:
    """Cheap presence check: GET a marker file under base_path, expect a non-HTML 200."""
    root = url if url.endswith("/") else url + "/"
    if base_path:
        root = urljoin(root, base_path.strip("/") + "/")
    for marker in markers:
        try:
            resp = await client.get(urljoin(root, marker), follow_redirects=False)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and "text/html" not in resp.headers.get("content-type", ""):
            return True
    return False


async def scan_dependents(
    store: Storage,
    client,
    url: str,
    path: str | None,
    parent: Project,
    registry: Registry,
    concurrency: int,
    progress=None,
) -> list[Finding]:
    from .scan import _log, _scan_one_project  # local import avoids an import cycle

    findings: list[Finding] = []
    spec = parent.dependents

    for name in spec.projects:
        project = registry.get(name)
        if project is None:
            continue
        meta = await store.get_project(name)
        if meta is None:
            continue  # dependent not indexed yet

        dep_path = _join(path or "", project.served_prefix)
        # Presence check before the full probe set, so absent plugins cost only a few requests.
        # Check the plugin's own assets (always served when installed) AND readme.txt — many sites
        # harden readme.txt away, but the assets must load for the plugin to work, and vice versa.
        markers = list(project.probe_files) + ["readme.txt", "readme.md"]
        if not await _present(client, url, dep_path, markers):
            continue
        _log(progress, f"[{parent.name}] dependent present: {name} ({dep_path})")

        finding = await _scan_one_project(
            store, client, url, dep_path, project, meta, "dependent", concurrency, progress
        )
        # Only report dependents we actually fingerprinted (something was served + matched).
        if finding.confidence.files_probed > 0:
            findings.append(finding)

    return findings
