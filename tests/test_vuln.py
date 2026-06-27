"""NVD/CVE enrichment: version normalization, CPE building, parsing, and result enrichment.

Hermetic — the NVD HTTP call is served by an httpx MockTransport, so no network is touched.
"""

from __future__ import annotations

import httpx
import pytest

from CommiPiste.models import Finding, MatchConfidence, Project, ScanResult
from CommiPiste.registry.loader import Registry
from CommiPiste.vuln import enrich_result
from CommiPiste.vuln.nvd import _virtual_match, normalize_version

PAYLOAD = {
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-0002",
                "published": "2023-02-01T00:00:00",
                "descriptions": [{"lang": "en", "value": "Medium severity issue"}],
                "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2023-0001",
                "published": "2023-01-01T00:00:00",
                "descriptions": [{"lang": "es", "value": "ignorado"}, {"lang": "en", "value": "Critical RCE"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2023-0003",
                "descriptions": [{"lang": "en", "value": "High severity issue"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            }
        },
    ],
}


def test_normalize_version() -> None:
    assert normalize_version("v27.1.11") == "27.1.11"
    assert normalize_version("6.4") == "6.4"
    assert normalize_version("release-9.0.0-rc1") == "9.0.0"
    assert normalize_version("nightly") is None
    assert normalize_version(None) is None


def test_virtual_match_builds_13_field_cpe() -> None:
    s = _virtual_match("cpe:2.3:a:nextcloud:nextcloud", "27.1.11")
    assert s == "cpe:2.3:a:nextcloud:nextcloud:27.1.11:*:*:*:*:*:*:*"
    assert len(s.split(":")) == 13


def _mock_client(payload, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "virtualMatchString" in request.url.params
        return httpx.Response(status, json=payload)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_enrich_result_attaches_summary() -> None:
    project = Project(name="nextcloud", repo_url="https://github.com/nextcloud/server",
                       cpe="cpe:2.3:a:nextcloud:nextcloud")
    registry = Registry({"nextcloud": project})
    result = ScanResult(
        url="https://cloud.example.org",
        findings=[
            Finding(software="nextcloud", detected_by="banner", version="27.1.11",
                    confidence=MatchConfidence(exact=True)),
            Finding(software="unknown-app", detected_by="banner", version="1.0"),  # no project/cpe
        ],
    )
    async with _mock_client(PAYLOAD) as client:
        await enrich_result(result, registry, sources=("nvd", "osv"), client=client)
    summary = result.findings[0].vulnerabilities
    assert summary is not None and summary.total == 3
    assert summary.by_severity == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}
    assert [v.cve_id for v in summary.top] == ["CVE-2023-0001", "CVE-2023-0003", "CVE-2023-0002"]
    assert summary.top[0].description == "Critical RCE"  # English picked over Spanish
    assert "3 known CVE" in summary.headline
    assert result.findings[1].vulnerabilities is None  # untouched (no cpe mapping)
