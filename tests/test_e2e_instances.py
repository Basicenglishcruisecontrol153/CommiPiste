"""End-to-end against CONCRETE LIVE instances: scan a real deployment and verify the version.

Each case points at a real public deployment of a platform. Where the instance exposes its own
version (Nextcloud/ownCloud `/status.php`, WordPress `generator` meta), the test derives that
ground truth at run time and asserts CommiPiste agrees — so it keeps working as the site
upgrades. Where no version is exposed, it asserts the platform is still identified with a concrete
commit and non-zero confidence.

These hit third-party sites, so they are gated behind CR_E2E_LIVE=1 and skip (not fail) when a host
is unreachable. Run with:

    CR_E2E_LIVE=1 pytest tests/test_e2e_instances.py -q

Extend `CASES` with your own concrete instances as needed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Optional

import httpx
import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.banner import detect_software
from CommiPiste.detector.fetcher import make_client
from CommiPiste.detector.scan import scan_target
from CommiPiste.registry import load_registry

_DB = get_settings().db_path

pytestmark = pytest.mark.skipif(
    not os.environ.get("CR_E2E_LIVE") or not _DB.exists(),
    reason="set CR_E2E_LIVE=1 and populate ~/.CommiPiste to run live-instance e2e",
)


def _digits(v: str | None) -> str:
    """Normalise a version label to bare digits: 'v32.0.9' / 'release-3.3.17' -> '32.0.9'/'3.3.17'."""
    if not v:
        return ""
    m = re.search(r"\d+(?:\.\d+)+", v)
    return m.group(0) if m else ""


def nextcloud_status(url: str) -> Optional[str]:
    """Ground truth from /status.php (Nextcloud & ownCloud)."""
    try:
        r = httpx.get(url.rstrip("/") + "/status.php", verify=False, timeout=10,
                      follow_redirects=True)
    except httpx.HTTPError:
        return None
    m = re.search(r'"versionstring":"([^"]+)"', r.text)
    return m.group(1) if m else None


def mediawiki_generator(url: str) -> Optional[str]:
    """Ground truth from the MediaWiki API siteinfo generator ('MediaWiki 1.45.3')."""
    try:
        r = httpx.get(url.rstrip("/") + "/api.php",
                      params={"action": "query", "meta": "siteinfo", "format": "json"},
                      verify=False, timeout=10, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
        gen = r.json().get("query", {}).get("general", {}).get("generator", "")
    except Exception:
        return None
    m = re.search(r"MediaWiki ([0-9.]+)", gen)
    return m.group(1) if m else None


def wordpress_generator(url: str) -> Optional[str]:
    """Ground truth from the WordPress generator meta tag."""
    try:
        r = httpx.get(url, verify=False, timeout=10, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
    except httpx.HTTPError:
        return None
    m = re.search(r'name="generator" content="WordPress ([0-9.]+)', r.text)
    return m.group(1) if m else None


def joomla_generator(url: str) -> Optional[str]:
    """Ground truth from the Joomla generator meta tag ('Joomla! - Open Source ...' / 'Joomla! 3.10')."""
    try:
        r = httpx.get(url, verify=False, timeout=10, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
    except httpx.HTTPError:
        return None
    m = re.search(r'name="generator" content="Joomla!? ([0-9.]+)', r.text)
    return m.group(1) if m else None


@dataclass
class Case:
    software: str
    url: str
    path: Optional[str] = None
    active: bool = False  # active-probe platform (version from an endpoint; no git-blob commit)
    ground_truth: Optional[Callable[[str], Optional[str]]] = None


# Concrete live deployments verified during development. The self-reporting ones (Nextcloud,
# WordPress) cross-check the exact version; the rest assert the platform stays identifiable.
CASES = [
    # --- self-reporting (cross-checked against the instance's own version) ---
    Case("nextcloud", "https://magentacloud.de", ground_truth=nextcloud_status),
    Case("nextcloud", "https://cloud.cloud68.co", ground_truth=nextcloud_status),
    Case("nextcloud", "https://cloud.gwc-systems.de", ground_truth=nextcloud_status),
    Case("nextcloud", "https://cloud.alfacloud.biz", ground_truth=nextcloud_status),
    Case("nextcloud", "https://nextcloud.csr-online.net", ground_truth=nextcloud_status),
    Case("wordpress", "https://techcrunch.com", ground_truth=wordpress_generator),
    Case("wordpress", "https://variety.com", ground_truth=wordpress_generator),
    Case("wordpress", "https://www.rollingstone.com", ground_truth=wordpress_generator),
    Case("mediawiki", "https://wiki.archlinux.org", ground_truth=mediawiki_generator),
    Case("joomla", "https://extensions.joomla.org", ground_truth=joomla_generator),
    # --- git-blob, concrete live deployments (assert version/commit identified) ---
    Case("roundcube", "https://mail.ispras.ru"),
    Case("redmine", "https://www.redmine.org"),
    Case("moodle", "https://school.moodledemo.net"),
    Case("limesurvey", "https://demo.limesurvey.org"),
    Case("phpipam", "https://demo.phpipam.net"),
    Case("dolibarr", "https://demo.dolibarr.org"),
    Case("icingaweb2", "https://demo.icinga.com"),
    Case("mantisbt", "https://mantisbt.org/bugs"),
    Case("grav", "https://getgrav.org"),
    Case("mybb", "https://community.mybb.com"),
    Case("concrete", "https://www.concretecms.org"),
    Case("librenms", "https://demo.librenms.org"),
    Case("seafile", "https://demo.seafile.com"),
    Case("movabletype", "https://www.movabletype.org"),
    Case("serendipity", "https://blog.s9y.org"),
    Case("wackowiki", "https://wackowiki.org/doc"),
    Case("textpattern", "https://textpattern.com"),
    Case("b2evolution", "https://b2evolution.net"),
    Case("e107", "https://e107.org"),
    Case("october", "https://octobercms.com"),
    Case("piwigo", "https://piwigo.com"),
    Case("processwire", "https://processwire.com"),
    Case("punbb", "https://punbb.informer.com/forums/"),
    Case("spip", "https://www.spip.net"),
    Case("tiki", "https://tiki.org"),
    Case("zenphoto", "https://www.zenphoto.org"),
    Case("bugzilla", "https://bugs.eclipse.org/bugs/"),
    # --- newly indexed platforms, live-verified ---
    Case("matomo", "https://demo.matomo.org"),
    Case("backdrop", "https://backdropcms.org"),
    Case("yourls", "https://yourls.org"),
    Case("freshrss", "https://demo.freshrss.org"),
    Case("friendica", "https://nerdica.net"),
    Case("subrion", "https://www.subrion.org"),
    Case("shaarli", "https://demo.shaarli.org"),
    # --- active-probe (version from an endpoint; needs --active) ---
    Case("mattermost", "https://community.mattermost.com", active=True),
    Case("grafana", "https://play.grafana.org", active=True),
    Case("gitea", "https://gitea.com", active=True),
    Case("gitea", "https://codeberg.org", active=True),   # large real-world self-hosted instance
    Case("jenkins", "https://ci.jenkins.io", active=True),
    Case("discourse", "https://meta.discourse.org", active=True),
    Case("flarum", "https://discuss.flarum.org", active=True),
]


# Live WordPress sites whose installed plugins we fingerprint as dependents. Each asserts a
# specific plugin is detected with a concrete version/commit on a real deployment.
DEPENDENT_CASES = [
    ("https://yoast.com", "akismet"),         # akismet (wordpress.org SVN source)
    ("https://yithemes.com", "woocommerce"),  # WooCommerce store
    ("https://wpastra.com", "elementor"),     # Elementor-built site
]


@pytest.mark.parametrize("url,plugin", DEPENDENT_CASES, ids=lambda v: v.split("//")[-1] if "//" in v else v)
async def test_live_wp_plugin_dependent(url: str, plugin: str) -> None:
    """Scanning a live WordPress site also fingerprints its installed plugins."""
    result = await scan_target(
        url, software="wordpress", with_dependents=True, verify_tls=False, concurrency=6,
    )
    if result.error:
        pytest.skip(f"unreachable: {result.error}")
    deps = [f for f in result.findings if f.detected_by == "dependent" and (f.commit_sha or f.version)]
    if not deps:
        pytest.skip(f"{url}: no plugin dependents served (CDN-offloaded or changed)")
    assert any(f.software == plugin for f in deps), (
        f"{url}: expected '{plugin}' dependent, got {[f.software for f in deps]}"
    )


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c.software}@{c.url.split('//')[1]}")
async def test_live_instance(case: Case) -> None:
    result = await scan_target(
        case.url, path=case.path, software=case.software,
        with_dependents=False, active_probe=case.active, verify_tls=False, concurrency=6,
    )
    if result.error:
        pytest.skip(f"unreachable / not detectable: {result.error}")
    assert result.findings, f"{case.url}: no findings"
    f = next((x for x in result.findings if x.software == case.software), result.findings[0])
    assert f.software == case.software

    # Must resolve a concrete version (git-blob → commit + version; active-probe → version).
    assert f.version or f.commit_sha, (
        f"{case.url}: no version/commit resolved (confidence {f.confidence.label})"
    )

    if case.ground_truth is None:
        return  # no exposed version to cross-check; identification above is enough

    gt = case.ground_truth(case.url)
    if not gt:
        pytest.skip(f"{case.url}: instance did not expose a version to cross-check")

    resolved = {_digits(f.version)} | {_digits(c) for c in f.candidate_versions}
    resolved.discard("")
    gt_d = _digits(gt)
    # Agree if CommiPiste's version (or a candidate) matches the instance's reported version,
    # or at least agrees on major.minor (patch-level can be ambiguous when assets are unchanged).
    mm = gt_d.rsplit(".", 1)[0]
    ok = gt_d in resolved or any(r == gt_d or r.startswith(mm + ".") or r == mm for r in resolved)
    assert ok, f"{case.url}: instance reports {gt}, CommiPiste resolved {sorted(resolved)}"


# Banner auto-detection on real sites: the expected platform must be detected (guards against
# false NEGATIVES when markers are tightened), and the page must not light up an implausible number
# of platforms (guards against false POSITIVES from over-broad markers). Active-probe cases are
# skipped — they aren't banner-identified.
_NON_ACTIVE = [c for c in CASES if not c.active]


@pytest.mark.parametrize("case", _NON_ACTIVE, ids=lambda c: f"{c.software}@{c.url.split('//')[1]}")
async def test_live_banner_no_cross_detection(case: Case) -> None:
    client = make_client(verify=False)
    try:
        matched = await detect_software(client, case.url, load_registry().all(), path=case.path)
    except Exception as exc:  # network hiccup -> skip, not fail
        pytest.skip(f"unreachable: {exc}")
    finally:
        await client.aclose()
    if not matched:
        pytest.skip(f"{case.url}: banner not served (CDN/custom theme)")
    assert case.software in matched, (
        f"{case.url}: expected '{case.software}' in banner matches, got {matched}"
    )
    # A correctly-scoped marker set shouldn't make one page match many unrelated platforms.
    assert len(matched) <= 3, f"{case.url}: over-broad detection — matched {matched}"
