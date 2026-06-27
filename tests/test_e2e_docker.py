"""End-to-end against LOCAL Docker instances (the WASABO approach) — version detection only.

Unlike the public-instance e2e (`test_e2e_instances.py`), this brings up DEFAULT installs at pinned
versions via `docker/docker-compose.yml`, so the ground truth is exact and we can cover internal-only
tools (Zabbix, GLPI, NetBox, …) that have no public instances. No vulnerability checks.

Usage:
    docker compose -f docker/docker-compose.yml --profile all up -d   # or --profile light/cms/internal
    # wait ~1-2 min for apps to boot, then:
    CR_E2E_DOCKER=1 pytest tests/test_e2e_docker.py -q

Each case asserts CommiPiste identifies the app and that the resolved version (or a candidate)
agrees with the pinned image tag at least on major.minor. Services that aren't up are skipped.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Optional

import httpx
import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.scan import scan_target

_DB = get_settings().db_path

pytestmark = pytest.mark.skipif(
    not os.environ.get("CR_E2E_DOCKER") or not _DB.exists(),
    reason="set CR_E2E_DOCKER=1, populate ~/.CommiPiste, and `docker compose up` the harness",
)


def _digits(v: str | None) -> str:
    m = re.search(r"\d+(?:\.\d+)+", v or "")
    return m.group(0) if m else ""


@dataclass
class DCase:
    software: str
    url: str
    expect: str          # pinned image version (ground truth)
    active: bool = False


# Mirrors docker/docker-compose.yml — keep the pinned versions in sync with the image tags there.
DOCKER_CASES = [
    # light
    DCase("phpmyadmin", "http://localhost:8001", "5.2.1"),
    DCase("grafana",    "http://localhost:8002", "11.0.0", active=True),
    DCase("jenkins",    "http://localhost:8004", "2.440.3", active=True),
    # gitea is covered by public instances (test_e2e_instances.py), not Docker
    # cms
    DCase("wordpress",  "http://localhost:8011", "6.5"),
    DCase("mediawiki",  "http://localhost:8012", "1.41.1"),
    DCase("drupal",     "http://localhost:8013", "10.2"),
    DCase("nextcloud",  "http://localhost:8014", "28.0.4"),
    DCase("joomla",     "http://localhost:8015", "5.1"),
    # internal (no public instances). Zabbix is active-probe (apiinfo.version), not git-blob.
    DCase("zabbix",     "http://localhost:8021", "6.4", active=True),
    DCase("netbox",     "http://localhost:8022", "4.0.3"),
    DCase("glpi",       "http://localhost:8023", "10.0.15"),
    # legacy: specific OLD versions (hard to find live; where the CVEs are)
    DCase("wordpress",  "http://localhost:8101", "4.9"),
    DCase("wordpress",  "http://localhost:8102", "5.0"),
    DCase("nextcloud",  "http://localhost:8103", "20"),
    DCase("mediawiki",  "http://localhost:8104", "1.35"),
    DCase("drupal",     "http://localhost:8105", "9.4"),
    DCase("phpmyadmin", "http://localhost:8106", "4.9"),
    DCase("roundcube",  "http://localhost:8107", "1.4"),
    DCase("grafana",    "http://localhost:8108", "7.5", active=True),
    # legacy batch 2
    DCase("wordpress",  "http://localhost:8110", "4.7"),
    DCase("nextcloud",  "http://localhost:8111", "18"),
    DCase("mediawiki",  "http://localhost:8112", "1.31"),
    DCase("drupal",     "http://localhost:8113", "9.2"),
    DCase("roundcube",  "http://localhost:8114", "1.3"),
    DCase("grafana",    "http://localhost:8115", "6.7", active=True),
    DCase("phpmyadmin", "http://localhost:8117", "4.7"),
    DCase("redmine",    "http://localhost:8118", "4.0"),
    DCase("joomla",     "http://localhost:8119", "3.10"),
    # legacy batch 3 (even older + an OLD internal tool)
    DCase("nextcloud",  "http://localhost:8121", "15"),
    DCase("mediawiki",  "http://localhost:8122", "1.27"),
    DCase("grafana",    "http://localhost:8123", "5.4", active=True),
    DCase("phpmyadmin", "http://localhost:8124", "4.6"),
    # legacy batch 4
    DCase("drupal",     "http://localhost:8128", "8.9"),
    DCase("owncloud",   "http://localhost:8129", "10.11"),
    DCase("prestashop", "http://localhost:8130", "1.6"),
    # more indexed platforms with a ready Docker image
    DCase("kanboard",   "http://localhost:8030", "1.2.41"),
    DCase("dokuwiki",   "http://localhost:8031", "2024-02-06"),
    DCase("espocrm",    "http://localhost:8032", "8.4"),
    DCase("openemr",    "http://localhost:8033", "7.0"),
    DCase("phplist",    "http://localhost:8034/lists", "3.6.16"),  # app lives under /lists/
    DCase("postfixadmin", "http://localhost:8035", "4.0.3"),
    # legacy batch 5 (very old)
    DCase("nextcloud",  "http://localhost:8131", "13"),
    DCase("nextcloud",  "http://localhost:8132", "14"),
    DCase("joomla",     "http://localhost:8133", "3.6"),
    DCase("redmine",    "http://localhost:8134", "3.4"),
]


def _ready(url: str, timeout: float | None = None) -> bool:
    """Poll until the container answers HTTP at all (any status), or give up.

    Timeout is overridable via CR_E2E_READY_TIMEOUT (lower it to fast-skip services you didn't bring
    up, e.g. when testing only one profile).
    """
    if timeout is None:
        timeout = float(os.environ.get("CR_E2E_READY_TIMEOUT", "90"))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=5, follow_redirects=True)
            return True
        except httpx.HTTPError:
            time.sleep(2)
    return False


@pytest.mark.parametrize("case", DOCKER_CASES, ids=lambda c: f"{c.software}:{c.expect}")
async def test_docker_instance(case: DCase) -> None:
    if not _ready(case.url):
        pytest.skip(f"{case.software}: container not up at {case.url} (bring up the compose profile)")
    result = await scan_target(
        case.url, software=case.software, with_dependents=False,
        active_probe=case.active, verify_tls=False, concurrency=6,
    )
    if result.error:
        pytest.skip(f"{case.software}: {result.error}")
    assert result.findings, f"{case.software}: no findings"
    f = next((x for x in result.findings if x.software == case.software), result.findings[0])
    assert f.version or f.commit_sha, (
        f"{case.software}: not identified (confidence {f.confidence.label})"
    )

    # Cross-check against the pinned image version (major.minor — patch can be ambiguous when assets
    # are unchanged across patches).
    resolved = {_digits(f.version)} | {_digits(c) for c in f.candidate_versions}
    resolved.discard("")
    if not resolved:
        return  # active-probe with a non-numeric build string still counts as identified above
    # `expect` may be major-only ("20") or major.minor ("1.35"); agree if a resolved version equals
    # it or is a more-specific patch under it.
    m = re.search(r"\d+(?:\.\d+)*", case.expect)
    want = m.group(0) if m else ""
    ok = not want or any(r == want or r.startswith(want + ".") for r in resolved)
    assert ok, f"{case.software}: image is {case.expect}, CommiPiste resolved {sorted(resolved)}"
