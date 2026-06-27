"""Vulnerability enrichment: map identified versions/commits to known advisories.

Optional, online post-scan step (kept separate from the core scan so fingerprinting stays
offline-capable and hermetically testable). Two complementary sources, merged into one deduplicated
summary per finding:

  - **NVD** — by CPE product + version (needs a ``cpe:`` mapping in the project's registry YAML).
  - **CVEDB** (Shodan) — also by CPE + version; keyless and not rate-limited, so it backfills the
    NVD when that 503s and catches CVEs the NVD's CPE applicability misses. Results union with NVD.
  - **OSV** (osv.dev) — by the identified git commit (no per-project mapping needed).

Enable from the CLI with ``--cve``. The default sources are **CVEDB + OSV** (both keyless and fast);
the NVD is opt-in (``--cve-source nvd`` or ``all``) because its rate-limited API is slow and CVEDB
already answers the same CPE+version query. Choose with ``--cve-source nvd|cvedb|osv|both|all``.
"""

from __future__ import annotations

import httpx

from ..models import ScanResult, VulnSummary
from ..registry import Registry
from .cvedb import backfill_scores, fetch_cvedb_many
from .merge import build_summary
from .nvd import fetch_nvd_many, normalize_version
from .osv import fetch_osv

__all__ = ["enrich_result", "enrich_results"]

DEFAULT_SOURCES = ("cvedb", "osv")  # fast + keyless; NVD is opt-in (slow, rate-limited)


async def enrich_result(
    result: ScanResult,
    registry: Registry,
    *,
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    api_key: str | None = None,
    max_cves: int = 10,
    client: httpx.AsyncClient | None = None,
) -> ScanResult:
    """Attach a merged :class:`VulnSummary` to each finding for which a source is applicable.

    NVD runs when the project has a ``cpe`` and the finding has a version; OSV runs whenever the
    finding has a commit. Findings for which neither applies are left untouched.
    """
    own = client is None
    client = client or httpx.AsyncClient(follow_redirects=True)
    try:
        for finding in result.findings:
            project = registry.get(finding.software)
            cpe = getattr(project, "cpe", None) if project else None

            vulns = []
            errors: list[str] = []
            used: list[str] = []
            nvd_url: str | None = None
            versions_checked = 0
            commits_checked = 0
            attempted = False

            # NVD is keyed by CPE + version. For a non-exact match we check EVERY candidate version
            # (best + candidate_versions), since a CVE fixed in a later candidate still affects the
            # earlier ones — symmetric with the OSV multi-commit check below.
            candidate_versions = [finding.version, *finding.candidate_versions]
            if "nvd" in sources and cpe and any(candidate_versions):
                attempted = True
                nv, err, url, vchecked = await fetch_nvd_many(
                    client, cpe, candidate_versions, api_key=api_key
                )
                versions_checked = vchecked
                if err and not nv:
                    errors.append(err)
                else:
                    vulns += nv
                    nvd_url = url
                    used.append("NVD")
                    if err:  # truncation note alongside results
                        errors.append(err)

            # CVEDB (Shodan): same CPE+version query as the NVD, keyless and un-throttled. Union with
            # NVD (merge dedups by CVE id) so it backfills NVD 503s and CPE-applicability gaps.
            if "cvedb" in sources and cpe and any(candidate_versions):
                attempted = True
                cv, cerr, cchecked = await fetch_cvedb_many(client, cpe, candidate_versions)
                versions_checked = max(versions_checked, cchecked)
                if cerr and not cv:
                    errors.append(cerr)
                else:
                    vulns += cv
                    used.append("CVEDB")
                    if cerr:
                        errors.append(cerr)

            # OSV is keyed by commit and needs no CPE. For a non-exact match we check EVERY candidate
            # commit (best + commit_range), so the summary covers the whole candidate set.
            candidate_commits = [finding.commit_sha, *finding.commit_range]
            candidate_commits = [c for c in candidate_commits if c]
            if "osv" in sources and candidate_commits:
                attempted = True
                ov, oerr, checked = await fetch_osv(client, commits=candidate_commits)
                commits_checked = checked
                if oerr and not ov:
                    errors.append(oerr)
                else:
                    vulns += ov
                    used.append("OSV")
                    if oerr:  # e.g. truncation note alongside results
                        errors.append(oerr)

            if not attempted:
                continue

            # Some advisories arrive without a usable score (e.g. OSV carrying a CVSS v4.0 vector we
            # don't compute locally). Backfill those from CVEDB's precomputed per-CVE score.
            if any(v.cvss_score is None for v in vulns):
                await backfill_scores(client, vulns)

            finding.vulnerabilities = build_summary(
                cpe,
                normalize_version(finding.version) or finding.version,
                vulns,
                nvd_url=nvd_url,
                sources=used,
                max_cves=max_cves,
                versions_checked=versions_checked,
                commits_checked=commits_checked,
                error="; ".join(errors) or None,
            )
    finally:
        if own:
            await client.aclose()
    return result


async def enrich_results(
    results: list[ScanResult],
    registry: Registry,
    *,
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    api_key: str | None = None,
    max_cves: int = 10,
) -> list[ScanResult]:
    """Enrich many scan results, sharing one HTTP client (sequential to respect rate limits)."""
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for result in results:
            await enrich_result(
                result, registry, sources=sources, api_key=api_key, max_cves=max_cves, client=client
            )
    return results
