#!/usr/bin/env python3
"""Generate docs/CATALOG.md from the registry + signature DB (single source of truth).

Replaces the hand-maintained, perpetually-stale CATALOG. Lists every platform with its detection
mechanism, per-project stats, repo, and (with --enrich) a one-line description + demo/test instance
pulled from the awesome-selfhosted-data catalog.

    python scripts/gen_catalog.py                 # offline: registry + DB only
    python scripts/gen_catalog.py --enrich         # + descriptions/demos from awesome-selfhosted

ponytail: reads are concurrent-safe (WAL), so it works even while an index job holds the write lock.
"""
from __future__ import annotations

import argparse
import io
import sqlite3
import sys
import tarfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from CommiPiste.config import get_settings          # noqa: E402
from CommiPiste.registry.loader import load_registry  # noqa: E402

ASH = "https://codeload.github.com/awesome-selfhosted/awesome-selfhosted-data/tar.gz/refs/heads/master"


def db_stats(db_path: Path) -> dict[str, tuple[int, int]]:
    """name -> (refs, signatures) for projects present in the signature DB (read-only)."""
    if not db_path.exists():
        return {}
    con = sqlite3.connect(db_path)  # normal read; WAL allows readers alongside a writer
    try:
        rows = con.execute(
            "SELECT p.name, "
            "(SELECT count(*) FROM refs r WHERE r.project_id=p.id), "
            "(SELECT count(*) FROM observations o WHERE o.project_id=p.id) "
            "FROM projects p"
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        con.close()
    return {n: (refs, sigs) for n, refs, sigs in rows}


def enrich() -> dict[str, tuple[str, str]]:
    """lowercased name -> (description, demo_url) from awesome-selfhosted-data (one tarball)."""
    import yaml
    raw = urllib.request.urlopen(ASH, timeout=60).read()
    out: dict[str, tuple[str, str]] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for m in tar:
            if m.isfile() and "/software/" in m.name and m.name.endswith(".yml"):
                d = yaml.safe_load(tar.extractfile(m).read()) or {}
                out[(d.get("name", "")).lower()] = (
                    (d.get("description") or "").strip(), d.get("demo_url") or "")
    return out


# Curated public demo / test instances, verified live (HTTP 2xx) at edit time. These take
# precedence over awesome-selfhosted `demo_url` and work without --enrich. Only genuinely open
# demos or sites running the app itself — not marketing/login pages.
DEMOS = {
    "bookstack": "https://demo.bookstackapp.com",
    "kimai": "https://demo.kimai.org",
    "immich": "https://demo.immich.app",
    "photoprism": "https://demo.photoprism.app",
    "nextcloud": "https://try.nextcloud.com",
    "mantisbt": "https://mantisbt.org/bugs/",
    "grafana": "https://play.grafana.org",
    "gitea": "https://try.gitea.io",
    "discourse": "https://try.discourse.org",
    "moodle": "https://school.moodledemo.net",
    "rocketchat": "https://open.rocket.chat",
    "phpmyadmin": "https://demo.phpmyadmin.net",
    "dolibarr": "https://demo.dolibarr.org",
    "matomo": "https://demo.matomo.cloud",
    "jellyfin": "https://demo.jellyfin.org/stable",
    "mastodon": "https://mastodon.social",
    "pixelfed": "https://pixelfed.social",
    "mealie": "https://demo.mealie.io",
    "joomla": "https://launch.joomla.org",
    "prestashop": "https://demo.prestashop.com",
    "redmine": "https://www.redmine.org",
    "forgejo": "https://code.forgejo.org",
    "searxng": "https://searx.be",
    "espocrm": "https://demo.espocrm.com",
    "tiki": "https://demo.tiki.org",
    "piwigo": "https://piwigo.org/demo",
    "bugzilla": "https://landfill.bugzilla.org/bugzilla-tip/",
    "netbox": "https://demo.netbox.dev",
    "librenms": "https://demo.librenms.org",
    "openemr": "https://demo.openemr.io",
    "limesurvey": "https://demo.limesurvey.org",
    "opencart": "https://demo.opencart.com",
    "ghost": "https://demo.ghost.io",
    "chamilo": "https://campus.chamilo.org",
    "ilias": "https://demo.ilias.de",
    "foswiki": "https://foswiki.org",
    "seafile": "https://demo.seafile.com",
    "phplist": "https://demo.phplist.org",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--enrich", action="store_true", help="fetch descriptions/demos (network)")
    ap.add_argument("-o", "--out", default="docs/CATALOG.md")
    args = ap.parse_args()

    reg = load_registry()
    stats = db_stats(get_settings().db_path)
    desc = enrich() if args.enrich else {}

    gitblob, probe = [], []
    for p in reg.all():
        d, demo = desc.get(p.name.lower(), ("", ""))
        demo = DEMOS.get(p.name.lower(), demo)
        if p.public_paths:           # git-blob (may ALSO have a version_probe fallback)
            refs, sigs = stats.get(p.name, (0, 0))
            kind = "plugin" if str(getattr(p.kind, "value", p.kind)) == "plugin" else "core"
            gitblob.append((p.name, kind, refs, sigs, p.repo_url, d, demo,
                            "✓" if refs else "▫️ not indexed"))
        elif p.version_probe:        # active-probe only
            path = (p.version_probe.paths or [""])[0] or "/"
            probe.append((p.name, path, p.repo_url, d, demo))

    lines = [f"# CATALOG — supported software ({len(reg.all())//100*100}+ platforms)", "",
             f"Generated by `scripts/gen_catalog.py` from the registry + signature DB. "
             f"**{len(gitblob)} git-blob** (passive, exact-commit) + **{len(probe)} active-probe** "
             f"(`--active`, version via endpoint).", ""]

    lines += ["## git-blob fingerprinting (passive)", "",
              "| Project | Kind | refs | sigs | Repo | Demo / test instance | Description |",
              "|---|---|--:|--:|---|---|---|"]
    for n, kind, refs, sigs, repo, d, demo, flag in sorted(gitblob):
        demo_md = f"[demo]({demo})" if demo.startswith("http") else ""
        lines.append(f"| {n} | {kind} | {refs or flag} | {sigs or ''} | {repo} | {demo_md} | {d} |")

    lines += ["", "## active-probe (version via endpoint, `--active`)", "",
              "| Project | Endpoint | Repo | Demo / test instance | Description |",
              "|---|---|---|---|---|"]
    for n, path, repo, d, demo in sorted(probe):
        demo_md = f"[demo]({demo})" if demo.startswith("http") else ""
        lines.append(f"| {n} | `{path}` | {repo} | {demo_md} | {d} |")
    lines.append("")

    Path(args.out).write_text("\n".join(lines))
    print(f"wrote {args.out}: {len(gitblob)} git-blob + {len(probe)} active-probe "
          f"({'enriched' if desc else 'no enrich'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
