"""CVSS-from-vector, the OSV source, and multi-source merge/dedup."""

from __future__ import annotations

import httpx
import pytest

from CommiPiste.models import Finding, MatchConfidence, Project, ScanResult
from CommiPiste.registry.loader import Registry
from CommiPiste.vuln import enrich_result
from CommiPiste.vuln.cvss import score_from_vector, severity_bucket
from CommiPiste.vuln.osv import _parse_osv, fetch_osv

# ---- CVSS ---------------------------------------------------------------- #


def test_score_from_vector() -> None:
    crit, sev = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert crit == 9.8 and sev == "CRITICAL"
    high, sev = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert high == 7.5 and sev == "HIGH"
    assert score_from_vector("not-a-vector") == (None, None)


def test_severity_bucket() -> None:
    assert severity_bucket(0.0) == "NONE"
    assert severity_bucket(3.9) == "LOW"
    assert severity_bucket(6.9) == "MEDIUM"
    assert severity_bucket(7.0) == "HIGH"
    assert severity_bucket(9.5) == "CRITICAL"


# ---- OSV ----------------------------------------------------------------- #

OSV_PAYLOAD = {
    "vulns": [
        {
            "id": "CVE-2025-68460",
            "summary": "XSS in Roundcube",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        },
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2026-25916"],
            "details": "First line is the summary.\nMore details here.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"}],
        },
    ]
}


def test_parse_osv_canonicalizes_cve_and_scores() -> None:
    vulns = _parse_osv(OSV_PAYLOAD)
    assert [v.cve_id for v in vulns] == ["CVE-2025-68460", "CVE-2026-25916"]  # alias resolved
    assert vulns[0].severity == "HIGH" and vulns[0].cvss_score == 7.5
    assert vulns[0].sources == ["OSV"]
    assert vulns[1].description == "First line is the summary."
    # GHSA-with-CVE-alias links to NVD; pure CVE links to NVD too.
    assert vulns[0].url.endswith("CVE-2025-68460")


@pytest.mark.asyncio
async def test_fetch_osv_by_commit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/query"
        import json

        assert json.loads(request.content)["commit"] == "deadbeef"
        return httpx.Response(200, json=OSV_PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        vulns, err, checked = await fetch_osv(client, commit="deadbeef")
    assert err is None and len(vulns) == 2 and checked == 1


@pytest.mark.asyncio
async def test_fetch_osv_multiple_candidate_commits_union() -> None:
    """Several candidate commits are checked and their advisories are unioned/deduped."""
    import json

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sha = json.loads(request.content)["commit"]
        seen.append(sha)
        # Each commit reports one (overlapping) advisory; union should dedup to 2 distinct.
        vid = "CVE-2025-68460" if sha == "aaa" else "GHSA-xxxx-yyyy-zzzz"
        return httpx.Response(200, json={"vulns": [v for v in OSV_PAYLOAD["vulns"] if v["id"] == vid]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        vulns, err, checked = await fetch_osv(client, commits=["aaa", "bbb", "aaa"])  # dup dropped
    assert checked == 2 and sorted(seen) == ["aaa", "bbb"]
    assert {v.cve_id for v in vulns} == {"CVE-2025-68460", "CVE-2026-25916"}


@pytest.mark.asyncio
async def test_fetch_osv_no_commit() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        vulns, err, checked = await fetch_osv(c, commit=None)
    assert vulns == [] and err and checked == 0


# ---- multi-source merge -------------------------------------------------- #

NVD_PAYLOAD = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-68460",  # also reported by OSV -> must dedup
                "descriptions": [{"lang": "en", "value": "XSS"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.2, "baseSeverity": "HIGH"}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2024-99999",  # NVD-only
                "descriptions": [{"lang": "en", "value": "SQLi"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
            }
        },
    ],
}


@pytest.mark.asyncio
async def test_enrich_merges_nvd_and_osv_and_dedups() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":  # OSV
            return httpx.Response(200, json=OSV_PAYLOAD)
        return httpx.Response(200, json=NVD_PAYLOAD)  # NVD

    project = Project(name="roundcube", repo_url="https://github.com/roundcube/roundcubemail",
                      cpe="cpe:2.3:a:roundcube:webmail")
    registry = Registry({"roundcube": project})
    result = ScanResult(
        url="https://mail.example.org",
        findings=[Finding(software="roundcube", detected_by="banner", version="1.6.11",
                          commit_sha="deadbeef", confidence=MatchConfidence(exact=True))],
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await enrich_result(result, registry, sources=("nvd", "osv"), client=client)

    v = result.findings[0].vulnerabilities
    assert v is not None
    assert set(v.sources) == {"NVD", "OSV"}
    ids = [c.cve_id for c in v.top]
    # 3 distinct: CVE-2025-68460 (both), CVE-2024-99999 (NVD), CVE-2026-25916 (OSV).
    assert sorted(ids) == ["CVE-2024-99999", "CVE-2025-68460", "CVE-2026-25916"]
    assert v.total == 3
    shared = next(c for c in v.top if c.cve_id == "CVE-2025-68460")
    assert set(shared.sources) == {"NVD", "OSV"}  # merged attribution
    assert shared.cvss_score == 7.5  # max(7.2 from NVD, 7.5 from OSV vector)


@pytest.mark.asyncio
async def test_enrich_osv_checks_all_candidate_commits() -> None:
    """For a non-exact match, OSV is queried for the best commit AND every commit_range candidate."""
    import json

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["commit"])
        return httpx.Response(200, json=OSV_PAYLOAD)

    project = Project(name="wp", repo_url="https://github.com/WordPress/WordPress")  # no CPE
    registry = Registry({"wp": project})
    result = ScanResult(
        url="https://blog.example.org",
        findings=[
            Finding(
                software="wp", detected_by="banner", version="6.9.4",
                commit_sha="c0", commit_range=["c0", "c1", "c2"],
                confidence=MatchConfidence(exact=False),
            )
        ],
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await enrich_result(result, registry, sources=("osv",), client=client)

    v = result.findings[0].vulnerabilities
    assert v is not None and v.sources == ["OSV"]
    assert v.commits_checked == 3 and sorted(seen) == ["c0", "c1", "c2"]  # deduped (c0 once)
