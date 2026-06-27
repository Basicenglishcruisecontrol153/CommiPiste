"""Look up known vulnerabilities for a matched version via the NVD (NIST) API 2.0.

Given a project's CPE product prefix (e.g. ``cpe:2.3:a:nextcloud:nextcloud``) and a detected
version, query https://services.nvd.nist.gov/rest/json/cves/2.0 for CVEs whose CPE match ranges
cover that version, and summarise them (counts by severity, most severe CVEs, a browsable NVD link).

Rate limits: the public API allows ~5 requests / 30s without a key and ~50 with one. Set the
``NVD_API_KEY`` environment variable (or pass ``api_key``) to raise the limit. A scan issues one
request per identified version, so the default unauthenticated limit is fine for interactive use.
"""

from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import quote_plus

import httpx

from ..models import Vulnerability

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
NVD_SEARCH = "https://nvd.nist.gov/vuln/search/results"

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def normalize_version(version: str | None) -> str | None:
    """Extract a dotted numeric version from a tag/label (``v27.1.11`` -> ``27.1.11``)."""
    if not version:
        return None
    m = _VERSION_RE.search(version)
    return m.group(0) if m else None


def _virtual_match(cpe_base: str, version: str) -> str:
    """Build a fully-specified CPE 2.3 string for ``virtualMatchString`` (pads missing fields)."""
    # cpe:2.3:a:vendor:product[:version...] — ensure exactly the 13 dot-fields with version set.
    parts = cpe_base.split(":")
    parts = (parts + ["*"] * 13)[:13]
    parts[5] = version  # the version field
    return ":".join(parts)


def _english(descriptions: list[dict]) -> str | None:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return descriptions[0].get("value") if descriptions else None


def _severity(metrics: dict) -> tuple[str | None, float | None]:
    """Pick a CVSS severity/score, preferring v3.1 → v3.0 → v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseSeverity"), data.get("baseScore")
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        e = entries[0]
        return e.get("baseSeverity"), e.get("cvssData", {}).get("baseScore")
    return None, None


def _parse_vulns(payload: dict) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        severity, score = _severity(cve.get("metrics", {}))
        vulns.append(
            Vulnerability(
                cve_id=cve_id,
                severity=severity,
                cvss_score=score,
                description=_english(cve.get("descriptions", [])),
                url=NVD_DETAIL + cve_id,
                published=cve.get("published"),
                sources=["NVD"],
            )
        )
    return vulns


def search_url(cpe_base: str, version: str) -> str:
    product = cpe_base.split(":")[4] if len(cpe_base.split(":")) > 4 else cpe_base
    return f"{NVD_SEARCH}?query={quote_plus(product + ' ' + version)}"


async def fetch_nvd(
    client: httpx.AsyncClient,
    cpe_base: str,
    version: str | None,
    *,
    api_key: str | None = None,
    timeout: float = 8.0,
) -> tuple[list[Vulnerability], str | None, int, str | None]:
    """Raw NVD fetch -> (vulnerabilities, error, total_results, search_url). Used by the merger."""
    clean = normalize_version(version)
    if not clean:
        return [], "no numeric version to look up", 0, None
    headers = {}
    api_key = api_key or os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    params = {"virtualMatchString": _virtual_match(cpe_base, clean), "resultsPerPage": 200}

    # NVD is flaky (503s, timeouts, transient WAF blocks), but we fail fast: one short retry for a
    # transient blip, then give up (the scan still reports the version, just without NVD enrichment).
    # Rate limits and hard HTTP errors return immediately.
    backoff = [0.5]
    last_err = "NVD request failed"
    for attempt in range(len(backoff) + 1):
        try:
            resp = await client.get(NVD_API, params=params, headers=headers, timeout=timeout)
        except httpx.HTTPError as exc:
            last_err = f"NVD request failed: {exc or type(exc).__name__}"  # timeouts stringify empty
        else:
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except ValueError as exc:
                    return [], f"NVD bad JSON: {exc}", 0, None
                vulns = _parse_vulns(payload)
                total = int(payload.get("totalResults", len(vulns)))
                return vulns, None, total, search_url(cpe_base, clean)
            if resp.status_code in (403, 429):
                return [], "NVD rate limit hit (set NVD_API_KEY to raise it)", 0, None
            if resp.status_code == 503:
                last_err = "NVD temporarily unavailable (HTTP 503) — retry later or set NVD_API_KEY"
            else:
                return [], f"NVD HTTP {resp.status_code}", 0, None
        if attempt < len(backoff):
            await asyncio.sleep(backoff[attempt])
    return [], last_err, 0, None


# Bound the per-finding NVD fan-out (candidate versions are adjacent patch releases). Sequential to
# respect the NVD rate limit (~5 req/30s unauth).
MAX_NVD_VERSIONS = 8


async def fetch_nvd_many(
    client: httpx.AsyncClient,
    cpe_base: str,
    versions: list[str | None],
    *,
    api_key: str | None = None,
    timeout: float = 8.0,
    max_versions: int = MAX_NVD_VERSIONS,
) -> tuple[list[Vulnerability], str | None, str | None, int]:
    """Check several candidate versions in the NVD -> (vulns, error, search_url, versions_checked).

    For a non-exact match, every candidate version is checked (a CVE fixed in a later candidate still
    affects the earlier ones), and the CVEs are unioned. Mirrors the OSV multi-commit behaviour.
    """
    vers: list[str] = []
    for v in versions:
        clean = normalize_version(v)
        if clean and clean not in vers:
            vers.append(clean)
    if not vers:
        return [], "no numeric version to look up", None, 0
    truncated = len(vers) - max_versions if len(vers) > max_versions else 0
    vers = vers[:max_versions]

    all_vulns: list[Vulnerability] = []
    errors: list[str] = []
    nvd_url: str | None = None
    for v in vers:
        nv, err, _total, url = await fetch_nvd(client, cpe_base, v, api_key=api_key, timeout=timeout)
        if err and not nv:
            errors.append(err)
        else:
            all_vulns += nv
            nvd_url = nvd_url or url
    if errors and not all_vulns:
        return [], errors[0], None, len(vers)
    note = f"NVD: checked {max_versions} of {len(vers) + truncated} candidate versions" if truncated else None
    return all_vulns, note, nvd_url, len(vers)
