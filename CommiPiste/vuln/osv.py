"""Look up vulnerabilities from OSV.dev — keyed off the identified git commit.

OSV (https://osv.dev) aggregates advisories (GHSA, CVE, distro, language ecosystems) and supports
querying by a git **commit hash**. That fits CommiPiste exactly: we fingerprint the deployed
commit, so we can ask OSV "which advisories' affected git ranges include this commit?" with no
per-project package/ecosystem mapping. Complementary to the NVD (different coverage), merged into one
summary.
"""

from __future__ import annotations

import asyncio

import httpx

from ..models import Vulnerability
from .cvss import score_from_vector

OSV_API = "https://api.osv.dev/v1/query"
OSV_VULN = "https://osv.dev/vulnerability/"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"

# When a match isn't pinned to one commit we check every candidate commit. Bounded so a wide range
# can't fan out into too many requests; the rest are reported as not-checked rather than silently
# dropped. (OSV also has POST /v1/querybatch — one request for many commits — but it returns only
# ids+modified, so we'd need a second round-trip per id for severity/description; per-commit
# /v1/query returns full advisories directly, which is simpler for the small candidate sets here.)
MAX_OSV_COMMITS = 16


def _canonical_cve(vuln_id: str, aliases: list[str]) -> str | None:
    """Prefer a CVE id (OSV ids are sometimes GHSA-… with the CVE in aliases) for cross-source dedup."""
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return None


def _osv_severity(severity: list[dict]) -> tuple[float | None, str | None]:
    """Best CVSS score/severity from OSV's vector list (it gives vectors, not numeric scores)."""
    best: tuple[float | None, str | None] = (None, None)
    for entry in severity or []:
        vector = entry.get("score") or ""
        score, sev = score_from_vector(vector)
        if score is not None and (best[0] is None or score > best[0]):
            best = (score, sev)
    return best


def _parse_osv(data: dict) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for v in data.get("vulns", []) or []:
        vid = v.get("id")
        if not vid:
            continue
        cve = _canonical_cve(vid, v.get("aliases") or [])
        score, sev = _osv_severity(v.get("severity") or [])
        desc = v.get("summary")
        if not desc and v.get("details"):
            desc = v["details"].strip().splitlines()[0]
        out.append(
            Vulnerability(
                cve_id=cve or vid,
                severity=sev,
                cvss_score=score,
                description=desc,
                url=(NVD_DETAIL + cve) if cve else (OSV_VULN + vid),
                published=v.get("published"),
                sources=["OSV"],
            )
        )
    return out


async def _query_one(
    client: httpx.AsyncClient, commit: str, timeout: float
) -> tuple[list[Vulnerability] | None, str | None]:
    try:
        resp = await client.post(OSV_API, json={"commit": commit}, timeout=timeout)
    except httpx.HTTPError as exc:
        return None, f"OSV request failed: {exc}"
    if resp.status_code == 429:
        return None, "OSV rate limit hit"
    if resp.status_code != 200:
        return None, f"OSV HTTP {resp.status_code}"
    try:
        return _parse_osv(resp.json()), None
    except ValueError as exc:
        return None, f"OSV bad JSON: {exc}"


async def fetch_osv(
    client: httpx.AsyncClient,
    *,
    commit: str | None = None,
    commits: list[str] | None = None,
    timeout: float = 20.0,
    concurrency: int = 5,
    max_commits: int = MAX_OSV_COMMITS,
) -> tuple[list[Vulnerability], str | None, int]:
    """Query OSV for one or several candidate commits -> (vulnerabilities, error, commits_checked).

    For a non-exact match, pass every candidate commit (``commits=``): OSV is checked for each and
    the advisories are unioned, so the summary covers the whole candidate set rather than a single
    guess. Concurrency is bounded; a candidate set larger than ``max_commits`` is truncated and noted.
    """
    pool = commits if commits is not None else ([commit] if commit else [])
    pool = list(dict.fromkeys(c for c in pool if c))  # dedup, keep order
    if not pool:
        return [], "no commit to query OSV with", 0
    truncated = len(pool) - max_commits if len(pool) > max_commits else 0
    pool = pool[:max_commits]

    sem = asyncio.Semaphore(max(1, concurrency))

    async def guarded(sha: str):
        async with sem:
            return await _query_one(client, sha, timeout)

    results = await asyncio.gather(*(guarded(s) for s in pool))
    vulns: list[Vulnerability] = []
    errors: list[str] = []
    for v, err in results:
        if v is None:
            errors.append(err)
        else:
            vulns += v
    if errors and not vulns:
        return [], errors[0], len(pool)
    note = f"OSV: checked {max_commits} of {len(pool) + truncated} candidate commits" if truncated else None
    return vulns, note, len(pool)
