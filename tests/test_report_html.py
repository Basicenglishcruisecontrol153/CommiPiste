"""The interactive HTML report renders the key evidence and is self-contained."""

from __future__ import annotations

from CommiPiste.models import (
    FileEvidence,
    Finding,
    MatchConfidence,
    ScanResult,
    Vulnerability,
    VulnSummary,
)
from CommiPiste.report_html import render_html


def _sample() -> ScanResult:
    return ScanResult(
        url="https://cloud.example.org",
        findings=[
            Finding(
                software="nextcloud",
                detected_by="banner",
                version="27.1.11",
                commit_sha="abcdef1234567890",
                commit_url="https://github.com/nextcloud/server/commit/abcdef1234567890",
                confidence=MatchConfidence(files_probed=4, files_matched=4, exact=True, score=1.0),
                files=[
                    FileEvidence(
                        rel_path="core/css/server.css",
                        oid="deadbeefcafebabe0000",
                        status="match",
                        pin=2,
                        url="https://github.com/nextcloud/server/blob/abcdef1234567890/core/css/server.css",
                    ),
                    FileEvidence(rel_path="core/js/dist/main.js", status="missing"),
                ],
                vulnerabilities=VulnSummary(
                    cpe="cpe:2.3:a:nextcloud:nextcloud",
                    version="27.1.11",
                    total=2,
                    by_severity={"CRITICAL": 1, "MEDIUM": 1},
                    sources=["NVD", "OSV"],
                    versions_checked=2,
                    commits_checked=4,
                    nvd_url="https://nvd.nist.gov/vuln/search/results?query=nextcloud+27.1.11",
                    top=[
                        Vulnerability(
                            cve_id="CVE-2023-0001",
                            severity="CRITICAL",
                            cvss_score=9.8,
                            description="A critical remote code execution flaw.",
                            url="https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
                            sources=["NVD", "OSV"],
                        )
                    ],
                ),
            )
        ],
    )


def test_render_html_is_self_contained_and_complete() -> None:
    html = render_html([_sample()])
    assert html.startswith("<!doctype html>")
    # Self-contained: styles and scripts are inline, no external stylesheet/script includes.
    assert "<style>" in html and "<script>" in html
    assert "<link" not in html
    assert "<script src" not in html
    # Core evidence is present.
    assert "nextcloud" in html
    assert "abcdef123456" in html  # short commit
    assert "core/css/server.css" in html
    assert "blob/abcdef1234567890/core/css/server.css" in html  # per-file link
    assert "Files checked" in html
    # Vulnerability section.
    assert "CVE-2023-0001" in html
    assert "CRITICAL" in html
    assert "nvd.nist.gov" in html
    # Multi-source attribution states exactly what each source checked.
    assert "NVD: 2 versions" in html
    assert "OSV: 4 candidate commits" in html
    assert '<span class="src">OSV</span>' in html
    # CVE column is kept on one line (no wrapping to several lines).
    assert "td.cve" in html and "white-space:nowrap" in html
    # Domain title is prefixed with "URL:"; confidence is labelled explicitly.
    assert "URL:" in html
    assert "confidence: high" in html
    # Header summarises the report in one sentence (old tagline removed).
    assert "git blob OID matching" not in html
    assert "the exact version and" in html
    # Interactive bits.
    assert 'id="flt"' in html and "onlyvuln" in html


def test_nvd_key_hint_and_html(monkeypatch) -> None:
    from CommiPiste.report import NVD_KEY_URL, nvd_key_hint

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    # NVD failure + no key -> actionable hint with the request URL.
    hint = nvd_key_hint("NVD temporarily unavailable (HTTP 503)")
    assert hint and "NVD_API_KEY" in hint and NVD_KEY_URL in hint
    # Non-NVD error, or key already set -> no hint.
    assert nvd_key_hint("OSV rate limit hit") is None
    monkeypatch.setenv("NVD_API_KEY", "x")
    assert nvd_key_hint("NVD temporarily unavailable (HTTP 503)") is None

    # The hint (with a clickable link) reaches the HTML report.
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    result = ScanResult(
        url="https://x.example",
        findings=[Finding(software="seafile", detected_by="banner", version="14.0.2",
                          confidence=MatchConfidence(files_probed=7, files_matched=7, exact=True),
                          commit_sha="abc",
                          vulnerabilities=VulnSummary(version="14.0.2", total=0, sources=["OSV"],
                                                      error="NVD temporarily unavailable (HTTP 503)"))],
    )
    html = render_html([result])
    assert NVD_KEY_URL in html and "export NVD_API_KEY" in html


def test_render_html_handles_errors_and_empty() -> None:
    results = [
        ScanResult(url="https://a.example", error="no known software detected by banner"),
        ScanResult(url="https://b.example", findings=[]),
        ScanResult(
            url="https://c.example",
            findings=[
                # Indexed project, but the target served none of its probe files.
                Finding(software="magento2", detected_by="banner", indexed=True,
                        confidence=MatchConfidence(files_probed=0, files_matched=0)),
                # Project genuinely not in the signature DB.
                Finding(software="piwigo", detected_by="banner", indexed=False,
                        confidence=MatchConfidence(files_probed=0, files_matched=0)),
            ],
        ),
    ]
    html = render_html(results)
    assert "no known software detected by banner" in html
    assert "no findings" in html
    # A detected-but-not-versioned unit reads "version not found", not a red "NONE".
    assert "version not found" in html
    # The two zero-probe cases are distinguished, not both labelled "not indexed".
    assert "no probe files served by the target" in html  # indexed magento2
    assert "not indexed" in html  # un-indexed piwigo
    assert html.count("section") >= 3
