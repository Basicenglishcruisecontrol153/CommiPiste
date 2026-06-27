"""Look up vulnerabilities via Shodan's CVEDB (https://cvedb.shodan.io) — by CPE + version.

A keyless, no-rate-limit alternative to the NVD for the *same* CPE-product-and-version query, which
makes it a reliable fallback when the NVD is throttling (503s). Queried per candidate version and
unioned, mirroring :mod:`CommiPiste.vuln.nvd` so results merge into the same deduplicated summary.

Coverage note: like the NVD, a CVE recorded without affected-version ranges won't come back from a
version-scoped query (e.g. Matomo), even though a product-level query lists it — this is upstream
data completeness, not a CVEDB limitation.
"""

from __future__ import annotations

import httpx

from ..models import Vulnerability
from .cvss import severity_bucket
from .nvd import NVD_DETAIL, normalize_version

CVEDB_API = "https://cvedb.shodan.io/cves"
CVEDB_DETAIL = "https://cvedb.shodan.io/cve/"

# Bound the per-finding fan-out over candidate versions (adjacent patch releases).
MAX_CVEDB_VERSIONS = 8


def _cpe23(cpe_base: str, version: str) -> str:
    """`cpe:2.3:a:vendor:product` (+ optional fields) -> the same with the version field set."""
    parts = cpe_base.split(":")
    if len(parts) <= 5:  # cpe:2.3:a:vendor:product -> append version
        return cpe_base + ":" + version
    parts[5] = version
    return ":".join(parts)


def _parse(payload: dict) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for c in payload.get("cves", []) or []:
        cid = c.get("cve_id")
        if not cid:
            continue
        score = c.get("cvss_v3") or c.get("cvss") or c.get("cvss_v2")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        out.append(
            Vulnerability(
                cve_id=cid,
                severity=severity_bucket(score),
                cvss_score=score,
                description=c.get("summary"),
                url=NVD_DETAIL + cid,  # canonical detail page (same as the NVD source -> clean dedup)
                published=c.get("published_time"),
                sources=["CVEDB"],
            )
        )
    return out


async def fetch_cvedb(
    client: httpx.AsyncClient,
    cpe_base: str,
    version: str | None,
    *,
    timeout: float = 8.0,
) -> tuple[list[Vulnerability], str | None, int]:
    """Raw CVEDB fetch for one version -> (vulnerabilities, error, total)."""
    clean = normalize_version(version)
    if not clean:
        return [], "no numeric version to look up", 0
    for attempt in range(2):  # one quick retry; CVEDB is keyless and usually fast
        try:
            resp = await client.get(CVEDB_API, params={"cpe23": _cpe23(cpe_base, clean)}, timeout=timeout)
        except httpx.HTTPError as exc:
            last = f"CVEDB request failed: {exc or type(exc).__name__}"
            continue
        if resp.status_code == 200:
            try:
                vulns = _parse(resp.json())
            except ValueError as exc:
                return [], f"CVEDB bad JSON: {exc}", 0
            return vulns, None, len(vulns)
        # CVEDB answers 404 ("No information available") when it has no CVEs for this CPE+version —
        # a legitimate empty result, not an error. Treat it as "no known vulnerabilities".
        if resp.status_code == 404:
            return [], None, 0
        last = f"CVEDB HTTP {resp.status_code}"
    return [], last, 0


async def fetch_cve_detail(client: httpx.AsyncClient, cve_id: str, *, timeout: float = 8.0) -> dict | None:
    """Fetch CVEDB's record for one CVE id, or None."""
    try:
        resp = await client.get(CVEDB_DETAIL + cve_id, timeout=timeout)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


async def backfill_scores(client: httpx.AsyncClient, vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Fill in CVSS scores still missing after merge, from CVEDB's per-CVE record.

    Needed because some sources (e.g. OSV) only carry a CVSS **v4.0 vector**, which we don't compute
    locally; CVEDB exposes the precomputed v4 score, so a cheap by-id lookup recovers the severity.
    """
    for v in vulns:
        if v.cvss_score is not None or not v.cve_id.startswith("CVE-"):
            continue
        detail = await fetch_cve_detail(client, v.cve_id)
        if not detail:
            continue
        score = detail.get("cvss_v4") or detail.get("cvss_v3") or detail.get("cvss")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        if score is not None:
            v.cvss_score = score
            v.severity = severity_bucket(score)
            if "CVEDB" not in v.sources:
                v.sources.append("CVEDB")
    return vulns


async def fetch_cvedb_many(
    client: httpx.AsyncClient,
    cpe_base: str,
    versions: list[str | None],
    *,
    max_versions: int = MAX_CVEDB_VERSIONS,
) -> tuple[list[Vulnerability], str | None, int]:
    """Check several candidate versions in CVEDB -> (vulns, error, versions_checked)."""
    vers: list[str] = []
    for v in versions:
        clean = normalize_version(v)
        if clean and clean not in vers:
            vers.append(clean)
    if not vers:
        return [], "no numeric version to look up", 0
    vers = vers[:max_versions]

    all_vulns: list[Vulnerability] = []
    errors: list[str] = []
    for v in vers:
        cv, err, _total = await fetch_cvedb(client, cpe_base, v)
        if err and not cv:
            errors.append(err)
        else:
            all_vulns += cv
    if errors and not all_vulns:
        return [], errors[0], len(vers)
    return all_vulns, None, len(vers)
