"""Tests for the Shodan CVEDB vulnerability source."""

from __future__ import annotations

import httpx
import pytest

from CommiPiste.vuln import cvedb
from CommiPiste.vuln.merge import build_summary


def test_cpe23_sets_version():
    assert cvedb._cpe23("cpe:2.3:a:matomo:matomo", "5.1.0") == "cpe:2.3:a:matomo:matomo:5.1.0"
    # already has a (wildcard) version field -> replace it
    assert cvedb._cpe23("cpe:2.3:a:v:p:*:*", "2.0") == "cpe:2.3:a:v:p:2.0:*"


def test_parse_maps_fields_and_severity():
    payload = {"cves": [
        {"cve_id": "CVE-2024-1", "summary": "x", "cvss_v3": 9.8, "published_time": "2024-01-01"},
        {"cve_id": "CVE-2024-2", "summary": "y", "cvss": 5.0},
        {"summary": "no id -> skipped"},
    ]}
    vulns = cvedb._parse(payload)
    assert [v.cve_id for v in vulns] == ["CVE-2024-1", "CVE-2024-2"]
    assert vulns[0].severity == "CRITICAL" and vulns[0].cvss_score == 9.8
    assert vulns[1].severity == "MEDIUM"
    assert vulns[0].sources == ["CVEDB"]
    assert vulns[0].url.endswith("CVE-2024-1")


@pytest.mark.asyncio
async def test_fetch_cvedb_http(httpserver, monkeypatch):
    httpserver.expect_request("/cves").respond_with_json(
        {"cves": [{"cve_id": "CVE-2023-9", "summary": "boom", "cvss_v3": 7.5}]}
    )
    monkeypatch.setattr(cvedb, "CVEDB_API", httpserver.url_for("/cves"))
    async with httpx.AsyncClient() as client:
        vulns, err, total = await cvedb.fetch_cvedb(client, "cpe:2.3:a:roundcube:webmail", "1.6.0")
    assert err is None and total == 1
    assert vulns[0].cve_id == "CVE-2023-9" and vulns[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_404_is_empty_not_error(httpserver, monkeypatch):
    # CVEDB returns 404 "No information available" when a CPE+version has no CVEs (e.g. seafile).
    httpserver.expect_request("/cves").respond_with_json({"detail": "No information available"}, status=404)
    monkeypatch.setattr(cvedb, "CVEDB_API", httpserver.url_for("/cves"))
    async with httpx.AsyncClient() as client:
        vulns, err, total = await cvedb.fetch_cvedb(client, "cpe:2.3:a:seafile:seafile", "14.0.2")
    assert vulns == [] and err is None and total == 0  # empty, NOT an error string


@pytest.mark.asyncio
async def test_fetch_cvedb_many_unions(httpserver, monkeypatch):
    httpserver.expect_request("/cves").respond_with_json(
        {"cves": [{"cve_id": "CVE-1", "cvss": 4.0}]}
    )
    monkeypatch.setattr(cvedb, "CVEDB_API", httpserver.url_for("/cves"))
    async with httpx.AsyncClient() as client:
        vulns, err, checked = await cvedb.fetch_cvedb_many(
            client, "cpe:2.3:a:v:p", ["1.0", "1.1", None, "1.0"]
        )
    assert err is None and checked == 2  # deduped to 1.0, 1.1
    assert all(v.cve_id == "CVE-1" for v in vulns)


@pytest.mark.asyncio
async def test_backfill_scores_from_cvedb(httpserver, monkeypatch):
    from CommiPiste.models import Vulnerability
    httpserver.expect_request("/cve/CVE-2026-30849").respond_with_json(
        {"cve_id": "CVE-2026-30849", "cvss_v4": 9.3, "cvss_v3": 9.8}
    )
    monkeypatch.setattr(cvedb, "CVEDB_DETAIL", httpserver.url_for("/cve/"))
    vulns = [Vulnerability(cve_id="CVE-2026-30849", url="u", sources=["OSV"])]  # no score
    async with httpx.AsyncClient() as client:
        await cvedb.backfill_scores(client, vulns)
    assert vulns[0].cvss_score == 9.3              # prefers v4
    assert vulns[0].severity == "CRITICAL"
    assert "CVEDB" in vulns[0].sources


def test_merge_dedups_cvedb_with_nvd():
    from CommiPiste.models import Vulnerability
    nvd = Vulnerability(cve_id="CVE-X", cvss_score=7.0, url="u", sources=["NVD"])
    cdb = Vulnerability(cve_id="CVE-X", cvss_score=9.0, url="u", sources=["CVEDB"])
    summ = build_summary("cpe:2.3:a:v:p", "1.0", [nvd, cdb], sources=["NVD", "CVEDB"])
    assert summ.total == 1                      # same CVE id -> one entry
    one = summ.top[0]
    assert set(one.sources) == {"NVD", "CVEDB"}  # sources unioned
    assert one.cvss_score == 9.0                 # highest score kept
