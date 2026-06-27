"""Guards against banner false positives — the recurring "marker too generic" bug class.

Three layers (all hermetic):
  1. Negative corpus: representative pages that merely *mention* or *embed* a platform (analytics
     trackers, framework tags, common English words) must yield NO banner match. This is where
     `Matomo`/`csrf-token`/`Vanilla`/`mantis`-style over-broad markers get caught.
  2. Static lint: no builtin banner marker may be a bare common-English/dictionary word or a known
     generic framework token.
  3. Self-detection sanity: a synthetic page carrying a platform's own markers detects it.
"""

from __future__ import annotations

import re

import httpx
import pytest

from CommiPiste.detector.banner import detect_software
from CommiPiste.registry import load_registry


# --- 1. negative corpus ---------------------------------------------------- #

# Each page is something a *non*-instance would serve. None should identify any platform (the value
# is a note on what historically false-matched).
NEGATIVE_PAGES = {
    "rails app with CSRF meta": (
        '<html><head><meta name="csrf-token" content="abc123"></head>'
        '<body>A generic Ruby on Rails application</body></html>'  # was: zabbix
    ),
    "site embedding Matomo analytics": (
        '<html><head><!-- Matomo Tag Manager -->'
        '<script>var _paq=window._paq||[];_paq.push(["trackPageView"]);</script>'
        '</head><body>Some company homepage</body></html>'  # was: matomo
    ),
    "site embedding Google Analytics": (
        '<html><head><script src="https://www.googletagmanager.com/gtag/js"></script>'
        '</head><body>Marketing site</body></html>'
    ),
    "blog written in vanilla JS": (
        '<html><body>This widget is written in vanilla JavaScript, no frameworks. '
        'Also: vanilla ice cream recipe.</body></html>'  # was: vanilla
    ),
    "page mentioning common words": (
        '<html><body>Photos of cacti and a praying mantis at the Tiki bar. '
        'Built with Pico.css. Gravitational lensing.</body></html>'  # was: cacti/mantis/tiki/pico/grav
    ),
    "gravatar avatars": (
        '<html><body><img src="https://www.gravatar.com/avatar/d4c74594"></body></html>'  # was: grav
    ),
    "plain static page": "<html><head><title>Hello</title></head><body>Welcome</body></html>",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("desc", list(NEGATIVE_PAGES), ids=lambda d: d)
async def test_negative_corpus_yields_no_detection(desc):
    page = NEGATIVE_PAGES[desc]

    def handler(request: httpx.Request) -> httpx.Response:
        # Landing page returns the trap; every marker sub-path 404s (no instance).
        if request.url.path in ("", "/"):
            return httpx.Response(200, text=page)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        matched = await detect_software(client, "https://trap.example", load_registry().all())
    assert matched == [], f"{desc!r} falsely detected {matched}"


# --- 2. static lint -------------------------------------------------------- #

# Common English / dictionary words that must never be a standalone banner marker (they appear on
# unrelated sites). Extend as new ones surface.
_COMMON_WORDS = {
    "vanilla", "grav", "pico", "cacti", "mantis", "gibbon", "tiki", "matomo", "piwik",
    "core", "admin", "api", "user", "page", "home", "blog", "forum", "wiki", "cms",
}
# Generic framework/library tokens present on huge numbers of sites.
_GENERIC_TOKENS = {"csrf-token", "jquery", "bootstrap", "viewport", "x-powered-by", "wp-content"}


def test_no_bare_common_word_or_generic_token_markers():
    offenders = []
    for p in load_registry().all():
        if not p.banners:
            continue
        for pat in p.banners.body_regex or []:
            low = pat.strip().lower()
            # "bare" = the marker is JUST the word, no anchoring punctuation/context.
            bare = re.sub(r"[\\^$.*+?()\[\]{}|]", "", pat.strip())
            is_bare = bare.lower() == low and not any(c in pat for c in '<>="/ ')
            if is_bare and low in _COMMON_WORDS:
                offenders.append(f"{p.name}: bare common word {pat!r}")
            if low in _GENERIC_TOKENS:
                offenders.append(f"{p.name}: generic token {pat!r}")
    assert not offenders, "over-broad banner markers:\n  " + "\n  ".join(offenders)


# --- 3. self-detection sanity --------------------------------------------- #

@pytest.mark.asyncio
@pytest.mark.parametrize("name,page", [
    ("matomo", '<html><body>/* Matomo # free/libre web analytics platform */</body></html>'),
    ("zabbix", '<html><head><link href="zabbix.css"></head><body>© Zabbix SIA</body></html>'),
    ("grav", '<html><head><meta name="generator" content="GravCMS"></head></html>'),
    ("mantisbt", '<html><body>Powered by Mantis Bug Tracker</body></html>'),
])
async def test_self_detection(name, page):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("", "/"):
            return httpx.Response(200, text=page)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        matched = await detect_software(client, "https://x.example", load_registry().all())
    assert name in matched, f"{name} should self-detect; got {matched}"
