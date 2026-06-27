"""Interactive `interactive-update` flow.

Checks whether the local signature DB is current, compares it to the latest published release
(GitHub Release `signatures.json` manifest), and then either downloads the prebuilt DB or rebuilds
it locally — every step gated by a confirmation. Uploading a new DB to the release is NOT done here;
that's a separate maintainer step (see scripts/publish-db.*).

Automation flags (for non-TTY use): `--check` (report only, exit 1 if a newer DB exists),
`--download` (download if newer, no prompts), `--yes` (assume yes to confirmations).
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn
from rich.prompt import Confirm

from . import dbfetch
from .config import Settings

try:
    import questionary
except ImportError:  # optional dependency; only needed for the interactive menus
    questionary = None

console = Console(highlight=False)  # we use explicit markup; avoid rich auto-coloring stray numbers
err = Console(stderr=True, highlight=False)


# --------------------------------------------------------------------------- #
# pure helpers (unit-tested)                                                    #
# --------------------------------------------------------------------------- #


def _parse_dt(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_newer(manifest: dict, local_build_date: str | None) -> bool:
    """True if the published manifest's build_date is strictly newer than the local one."""
    remote = _parse_dt(manifest.get("build_date"))
    if remote is None:
        return False  # can't tell -> treat as not-newer (don't nag)
    local = _parse_dt(local_build_date)
    return local is None or remote > local


def is_today(iso: str | None) -> bool:
    dt = _parse_dt(iso)
    return dt is not None and dt.date() == datetime.now(timezone.utc).date()


# --------------------------------------------------------------------------- #
# entry point                                                                  #
# --------------------------------------------------------------------------- #


def interactive_update(
    settings: Settings,
    registry,
    *,
    assume_yes: bool = False,
    download: bool = False,
    check: bool = False,
) -> int:
    """Run the update flow. Returns a process exit code."""
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    projects = dbfetch._safe_project_count(settings.db_path)
    db_exists = projects > 0

    if check:
        return _check_only(settings)

    if not interactive and not (download or assume_yes):
        err.print(
            "[red]interactive-update needs a TTY.[/red] "
            "Use --check, --download, or --yes for non-interactive runs."
        )
        return 2

    # 0. No local DB at all -> straight to acquiring one (manifest is best-effort, for metadata).
    if not db_exists:
        console.print("No local database found.")
        try:
            manifest = dbfetch.fetch_manifest()
        except dbfetch.DBFetchError:
            manifest = None
        return _choose_update(settings, registry, assume_yes, download, interactive, manifest=manifest)

    # 1. Freshness guard: acquired today?
    if is_today(dbfetch.local_acquired_date(settings)) and not (assume_yes or download):
        if not _confirm(
            "The database was downloaded today. Are you sure you want to run an update?",
            default=False, assume_yes=assume_yes,
        ):
            console.print("Nothing to do.")
            return 0
    else:
        console.print(
            f"Local database: built {dbfetch.local_build_date(settings) or 'unknown'}, "
            f"{projects} projects."
        )

    # 2. Compare to the latest published release.
    try:
        with err.status("Checking the latest published database…"):
            manifest = dbfetch.fetch_manifest()
    except dbfetch.DBFetchError as exc:
        err.print(f"[yellow]Couldn't reach the release server:[/yellow] {exc}")
        if interactive and _confirm("Update manually instead?", default=True, assume_yes=assume_yes):
            return _manual_update(settings, registry, assume_yes)
        return 1

    local_bd = dbfetch.local_build_date(settings)
    if not is_newer(manifest, local_bd):
        console.print(
            f"You already have the latest database (built {local_bd or 'unknown'}, "
            f"{projects} projects). Nothing to update."
        )
        return 0
    console.print(
        f"A newer database is available: built {manifest.get('build_date')}, "
        f"{manifest.get('projects')} projects (yours: {local_bd or 'unknown'})."
    )
    return _choose_update(settings, registry, assume_yes, download, interactive, manifest=manifest)


# --------------------------------------------------------------------------- #
# steps                                                                        #
# --------------------------------------------------------------------------- #


def _confirm(msg: str, *, default: bool, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    return Confirm.ask(msg, default=default)


def _check_only(settings: Settings) -> int:
    local_bd = dbfetch.local_build_date(settings)
    projects = dbfetch._safe_project_count(settings.db_path)
    try:
        manifest = dbfetch.fetch_manifest()
    except dbfetch.DBFetchError as exc:
        err.print(f"[yellow]Couldn't reach the release server:[/yellow] {exc}")
        return 2
    if not db_present(settings):
        console.print(f"No local database. Latest published: {manifest.get('build_date')} "
                      f"({manifest.get('projects')} projects).")
        return 1
    if is_newer(manifest, local_bd):
        console.print(f"Update available: local {local_bd or 'unknown'} ({projects} projects) -> "
                      f"published {manifest.get('build_date')} ({manifest.get('projects')} projects).")
        return 1
    console.print(f"Up to date (built {local_bd or 'unknown'}, {projects} projects).")
    return 0


def db_present(settings: Settings) -> bool:
    return dbfetch._safe_project_count(settings.db_path) > 0


def _choose_update(settings, registry, assume_yes, download, interactive, *, manifest) -> int:
    if download or not interactive:
        return _do_download(settings, registry, manifest)
    if questionary is None:
        err.print("[red]install questionary for the interactive menu:[/red] pip install questionary")
        return 2
    choice = questionary.select(
        "How would you like to update?",
        choices=["Download the prebuilt database (recommended)", "Update manually"],
    ).ask()
    if choice is None:
        return 1
    if choice.startswith("Download"):
        return _do_download(settings, registry, manifest)
    return _manual_update(settings, registry, assume_yes)


def _do_download(settings: Settings, registry, manifest: dict | None) -> int:
    m = manifest or {}
    src = m.get("gz_url") or None  # manifest's explicit asset URL, else resolve_source default
    try:
        with Progress(
            TextColumn("[dim]downloading database[/dim]"), BarColumn(), DownloadColumn(),
            TransferSpeedColumn(), console=err, transient=True,
        ) as prog:
            task = prog.add_task("dl", total=None)
            dest, count = dbfetch.fetch_db(
                settings, src, force=True,
                build_date=m.get("build_date"), expected_sha256=m.get("db_sha256"),
                progress=lambda d, t: prog.update(task, completed=d, total=t),
            )
    except dbfetch.DBFetchError as exc:
        err.print(f"[red]{exc}[/red]")
        return 1
    console.print(f"[green]Updated[/green] to {m.get('build_date') or 'latest'} ({count} projects).")
    _reindex_local_projects(settings, registry)
    return 0


def _reindex_local_projects(settings, registry) -> None:
    """Re-index local-registry projects (e.g. autoindexed targets) absent from the just-downloaded
    DB, so the download doesn't silently drop them. tags-only — fast and the project's own default."""
    if registry is None:
        return
    have = set(_indexed_platforms(settings, registry))
    missing = [
        p.name for p in registry.all()
        if getattr(p, "is_local", False) and getattr(p, "public_paths", None) and p.name not in have
    ]
    if not missing:
        return
    console.print(f"[dim]restoring {len(missing)} local project(s) not in the downloaded DB…[/dim]")
    asyncio.run(_run_index(settings, registry, missing, update=False, tags_only=True))


def _manual_update(settings, registry, assume_yes) -> int:
    if questionary is None:
        err.print("[red]install questionary for the interactive menu:[/red] pip install questionary")
        return 2
    choices = []
    if db_present(settings):
        choices.append("Refresh latest release tags for indexed platforms (incremental)")
    choices.append("Rebuild the database myself (choose platforms)")
    choice = questionary.select("Manual update — choose:", choices=choices).ask()
    if choice is None:
        return 1
    if choice.startswith("Refresh"):
        return _refresh_tags(settings, registry, assume_yes)
    return _rebuild(settings, registry, assume_yes)


def _git_platforms(registry) -> list[str]:
    """Names of git-blob-indexable platforms (have public_paths; not active-probe-only)."""
    return sorted(p.name for p in registry.all() if getattr(p, "public_paths", None))


def _indexed_platforms(settings, registry) -> list[str]:
    """git-blob platforms that already have rows in the DB (candidates for incremental refresh)."""
    import sqlite3
    try:
        conn = sqlite3.connect(settings.db_path)
        have = {r[0] for r in conn.execute("SELECT name FROM projects")}
        conn.close()
    except sqlite3.Error:
        have = set()
    return [n for n in _git_platforms(registry) if n in have]


def _refresh_tags(settings, registry, assume_yes) -> int:
    names = _indexed_platforms(settings, registry)
    if not names:
        console.print("No indexed git-blob platforms to refresh.")
        return 0
    picks = questionary.checkbox("Select platforms to refresh (fetch new tags):", choices=names).ask()
    if not picks:
        console.print("Nothing selected.")
        return 0
    if not _confirm(
        f"This will `git fetch` and index new tags for {len(picks)} platform(s). Continue?",
        default=True, assume_yes=assume_yes,
    ):
        return 0
    asyncio.run(_run_index(settings, registry, picks, update=True, tags_only=True))
    _record_local_build(settings)
    return 0


def _rebuild(settings, registry, assume_yes) -> int:
    picks = questionary.checkbox(
        "Select platforms to (re)build:", choices=_git_platforms(registry)
    ).ask()
    if not picks:
        console.print("Nothing selected.")
        return 0
    mode = questionary.select(
        "Indexing mode:",
        choices=[
            "Release tags only (faster, version-level)",
            "Full commit history (slower, commit-level precision)",
        ],
    ).ask()
    if mode is None:
        return 1
    tags_only = mode.startswith("Release")
    if not _confirm(
        f"Index {len(picks)} platform(s), {'tags-only' if tags_only else 'full history'}. Proceed?",
        default=True, assume_yes=assume_yes,
    ):
        return 0
    asyncio.run(_run_index(settings, registry, picks, update=False, tags_only=tags_only))
    _record_local_build(settings)
    return 0


async def _run_index(settings, registry, names, *, update: bool, tags_only: bool) -> None:
    from .indexer.builder import index_project

    for n in names:
        proj = registry.get(n)
        if proj is None:
            continue
        console.print(f"[dim]· indexing {n}…[/dim]")
        try:
            stats = await index_project(
                proj, settings=settings, update=update, tags_only=tags_only
            )
            console.print(f"[green]✓[/green] {n}: {stats.stats}")
        except Exception as exc:  # one platform failing shouldn't abort the batch
            err.print(f"[red]✗ {n}: {exc}[/red]")


def _record_local_build(settings: Settings) -> None:
    """After a local (re)build, mark the DB as locally built today."""
    now = dbfetch._now_iso()
    dbfetch.write_local_meta(settings, {
        "acquired_at": now,
        "build_date": now,
        "source": "local-build",
        "projects": dbfetch._safe_project_count(settings.db_path),
    })
