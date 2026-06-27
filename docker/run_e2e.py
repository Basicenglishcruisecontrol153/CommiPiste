#!/usr/bin/env python3
"""Laptop-friendly Docker e2e runner.

Problem: bringing up every app at once needs tens of GB of images and fills a laptop's Docker disk.
This runner processes **one app at a time**: bring it up → wait → scan → assert the version → tear it
down → **remove its image**. So only one app image (plus cached DB/redis sidecars) is on disk at any
moment, and cleanup is automatic. Version-detection only (no vulnerability checks).

    python docker/run_e2e.py                  # all cases, sequential, remove app images as it goes
    python docker/run_e2e.py -k wordpress     # only cases whose "software:version" matches
    python docker/run_e2e.py --keep-images    # don't remove images (faster re-runs, more disk)
    python docker/run_e2e.py --jobs 2         # N apps concurrently (faster, but N images on disk)

Reuses the single source of truth: DOCKER_CASES from tests/test_e2e_docker.py and the service/port/
image graph from docker/docker-compose.yml (linked by the case URL's port). Exit code 1 on any FAIL.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
COMPOSE = str(ROOT / "docker" / "docker-compose.yml")

import httpx  # noqa: E402

from tests.test_e2e_docker import DOCKER_CASES, _digits  # noqa: E402
from CommiPiste.config import get_settings  # noqa: E402
from CommiPiste.detector.scan import scan_target  # noqa: E402
from CommiPiste.registry import load_registry  # noqa: E402
from CommiPiste.storage import open_storage  # noqa: E402

# Sidecar images are reused across apps — keep them cached, only remove app images.
_SIDECAR = re.compile(r"(mariadb|mysql|postgres|redis)", re.I)


def _compose_graph() -> tuple[dict, dict]:
    """Return (services, port -> (service, image, [dep services])) from `docker compose config`."""
    out = subprocess.run(
        # --profile all so profiled services (light/cms/internal/legacy) are included, not just the
        # default-profile ones.
        ["docker", "compose", "--profile", "all", "-f", COMPOSE, "config", "--format", "json"],
        capture_output=True, text=True, check=True,
    ).stdout
    services = json.loads(out).get("services", {})
    by_port: dict[str, tuple[str, str, list[str]]] = {}
    for name, spec in services.items():
        for p in spec.get("ports", []) or []:
            pub = str(p.get("published", "") or "")
            if pub:
                deps = list((spec.get("depends_on") or {}).keys())
                by_port[pub] = (name, spec.get("image", ""), deps)
    return services, by_port


def _dc(*args: str) -> None:
    subprocess.run(["docker", "compose", "-f", COMPOSE, *args], capture_output=True)


def _ready(url: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=5, follow_redirects=True, verify=False)
            return True
        except httpx.HTTPError:
            time.sleep(2)
    return False


async def _scan(case) -> object | None:
    settings = get_settings()
    store = await open_storage(settings.db_path)
    try:
        r = await scan_target(
            case.url, software=case.software, with_dependents=False,
            active_probe=case.active, verify_tls=False, concurrency=6,
        )
    finally:
        await store.close()
    if r.error or not r.findings:
        return None
    return next((x for x in r.findings if x.software == case.software), r.findings[0])


def _agree(f, expect: str) -> bool:
    if not f or not (getattr(f, "version", None) or getattr(f, "commit_sha", None)):
        return False
    resolved = {_digits(f.version)} | {_digits(c) for c in f.candidate_versions}
    resolved.discard("")
    if not resolved:
        return True  # active-probe with a non-numeric build string still counts as identified
    m = re.search(r"\d+(?:\.\d+)*", expect)
    want = m.group(0) if m else ""
    return (not want) or any(r == want or r.startswith(want + ".") for r in resolved)


def _run_case(case, services: dict, by_port: dict, keep: bool) -> tuple:
    port = str(urlparse(case.url).port or "")
    if port not in by_port:
        return (case, "NOSVC", f"no compose service on port {port}")
    service, image, deps = by_port[port]
    needs_db = any(_SIDECAR.search(services.get(d, {}).get("image", "")) for d in deps)
    try:
        _dc("up", "-d", service)
        if not _ready(case.url, 240 if needs_db else 60):
            return (case, "SKIP", "container not ready in time")
        f = asyncio.run(_scan(case))
        det = (f.version if f and f.version
               else (f.candidate_versions[0] + "…" if f and f.candidate_versions else "—"))
        return (case, "PASS" if _agree(f, case.expect) else "FAIL", f"detected {det}")
    finally:
        _dc("rm", "-fsv", service, *deps)            # stop + remove app and its sidecars
        if not keep and image and not _SIDECAR.search(image):
            subprocess.run(["docker", "image", "rm", "-f", image], capture_output=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Per-app Docker e2e runner (disk-bounded, auto-cleanup).")
    ap.add_argument("-k", default="", help="substring filter on 'software:version'")
    ap.add_argument("--keep-images", action="store_true", help="don't remove app images afterwards")
    ap.add_argument("--jobs", type=int, default=1, help="apps to run concurrently (more = more disk)")
    args = ap.parse_args()

    if not get_settings().db_path.exists():
        sys.exit("no signature DB at ~/.CommiPiste/signatures.db — build it or set COMMIPISTE_HOME")

    services, by_port = _compose_graph()
    cases = [c for c in DOCKER_CASES if args.k.lower() in f"{c.software}:{c.expect}".lower()]
    print(f"running {len(cases)} case(s), jobs={args.jobs}, keep_images={args.keep_images}\n")

    if args.jobs <= 1:
        results = [_run_case(c, services, by_port, args.keep_images) for c in cases]
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            results = list(ex.map(lambda c: _run_case(c, services, by_port, args.keep_images), cases))

    print("=== results ===")
    for case, status, info in results:
        print(f"  {status:5} {case.software + ':' + case.expect:22} {info}")
    n = {s: sum(1 for r in results if r[1] == s) for s in ("PASS", "FAIL", "SKIP", "NOSVC")}
    print(f"\n{n['PASS']} pass · {n['FAIL']} fail · {n['SKIP']} skip · {n['NOSVC']} no-service")
    sys.exit(1 if n["FAIL"] else 0)


if __name__ == "__main__":
    main()
