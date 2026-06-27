"""Regression tests for three fixes:

  1. Matomo banner precision — must not false-positive on a site that merely embeds the Matomo
     analytics tracker ("Matomo Tag"), only on the Matomo app itself. Also guards the YAML pitfall
     where an unquoted ``#`` silently truncated the marker to the bare word "Matomo".
  2. The "no probe files served" report line no longer points at the README.
  3. The human report / batch output renders cleanly (printed after the scan, not interleaved).
"""

from __future__ import annotations

import re

import httpx
import pytest
from rich.console import Console

from CommiPiste.detector.banner import detect_software
from CommiPiste.models import Finding, MatchConfidence, ScanResult
from CommiPiste.registry import load_registry
from CommiPiste.report import print_batch_summary, print_human


# --- 1. Matomo banner precision -------------------------------------------- #

def _matomo_regexes() -> list[str]:
    return load_registry().get("matomo").banners.body_regex


def test_matomo_banner_markers_are_quoted_not_truncated():
    """The YAML `#` must be quoted, so the marker is the full 'Matomo # free', not bare 'Matomo'."""
    rx = _matomo_regexes()
    assert "Matomo" not in rx, "bare 'Matomo' substring would match any analytics-embedding site"
    assert any("Matomo # free" in r for r in rx)


def test_matomo_banner_ignores_embedded_tracker():
    rx = _matomo_regexes()
    # Snippet a site embeds when it *uses* Matomo analytics (the concretecms.org false positive).
    tracker = '<!-- Matomo Tag Manager --><script>var _paq=window._paq||[];</script>'
    assert not any(re.search(r, tracker) for r in rx)


def test_matomo_banner_matches_the_app():
    rx = _matomo_regexes()
    app_page = '/* Matomo # free/libre web analytics platform */'
    assert any(re.search(r, app_page) for r in rx)


@pytest.mark.asyncio
async def test_detect_software_no_matomo_on_analytics_site():
    """End-to-end through detect_software: a concrete-CMS-like page embedding Matomo analytics must
    detect `concrete`, never `matomo`."""
    page = (
        '<html><head><meta name="generator" content="Concrete CMS">'
        '<!-- Matomo Tag Manager --><script>var _paq=[];</script></head>'
        '<body>Powered by Concrete CMS</body></html>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=page)

    reg = load_registry()
    cands = [reg.get(n) for n in ("matomo", "concrete")]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        matched = await detect_software(client, "https://x.example", cands)
    assert "matomo" not in matched
    assert "concrete" in matched


# --- 2. report text -------------------------------------------------------- #

def _render(finding: Finding) -> str:
    console = Console(record=True, width=100, highlight=False)
    print_human(ScanResult(url="https://x.example", findings=[finding]), console)
    return console.export_text()


def test_no_probe_files_message_drops_readme_reference():
    f = Finding(
        software="concrete", detected_by="banner", indexed=True,
        confidence=MatchConfidence(files_probed=0),
    )
    out = _render(f)
    assert "no probe files served" in out
    assert "README" not in out
    assert "not fingerprintable" not in out


def test_not_indexed_message_points_at_db_setup():
    f = Finding(
        software="matomo", detected_by="banner", indexed=False,
        confidence=MatchConfidence(files_probed=0),
    )
    out = _render(f)
    assert "not indexed" in out
    assert "COMMIPISTE_DB_URL" in out


# --- 3. report renders cleanly (regression for the spinner-bleed fix) ------ #

def test_human_report_has_bold_field_labels_and_clean_header():
    import io

    f = Finding(
        software="mantisbt", detected_by="banner", version="2.28.3",
        commit_sha="c96c87958449aa", commit_url="https://github.com/x/y/tree/c96c87958449aa",
        confidence=MatchConfidence(files_probed=49, files_matched=46, score=0.94),
    )
    plain_console = Console(record=True, width=100, highlight=False)
    print_human(ScanResult(url="https://mantisbt.example", findings=[f]), plain_console)
    plain = plain_console.export_text()
    assert "https://mantisbt.example" in plain          # header present
    assert "version:" in plain and "2.28.3" in plain
    assert "commit:" in plain

    # Force a terminal to a buffer so bold renders as ANSI -> confirm the field labels are bold.
    ansi = io.StringIO()
    tconsole = Console(file=ansi, force_terminal=True, width=100, highlight=False)
    print_human(ScanResult(url="https://mantisbt.example", findings=[f]), tconsole)
    assert "\x1b[1m" in ansi.getvalue()  # at least one bold sequence (the field labels)


def test_url_normalizer_defaults_to_https():
    from CommiPiste.detector.scan import _normalize_url
    assert _normalize_url("www.redmine.org") == "https://www.redmine.org"
    assert _normalize_url("  example.io ") == "https://example.io"
    assert _normalize_url("http://x.org") == "http://x.org"     # explicit scheme kept
    assert _normalize_url("https://x.org") == "https://x.org"


def test_batch_summary_renders_rows():
    results = [
        ScanResult(url="https://a.example", findings=[
            Finding(software="matomo", detected_by="banner", version="5.11.2",
                    commit_sha="abcdef123456", confidence=MatchConfidence())]),
        ScanResult(url="https://b.example", error="unreachable"),
    ]
    console = Console(record=True, width=120, highlight=False)
    print_batch_summary(results, console)
    out = console.export_text()
    assert "a.example" in out and "matomo" in out and "5.11.2" in out
    assert "b.example" in out and "unreachable" in out
