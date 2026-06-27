"""CommiPiste command-line interface (Typer)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import get_settings
from .indexer.builder import index_project as _index_project
from .models import Project
from .registry import load_registry
from .registry.loader import add_local_project
from .report import print_batch_summary, print_human, to_json

app = typer.Typer(
    add_completion=False,
    help="OSINT fingerprinting of open-source web software versions via git blob OIDs.",
)
registry_app = typer.Typer(help="Manage project definitions.")
app.add_typer(registry_app, name="registry")

# highlight=False: we color output ourselves with explicit markup; rich's auto-highlighter otherwise
# colorizes stray numbers/hex (e.g. "0x100" in a filename) inconsistently and meaninglessly.
console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


def _derive_name(repo_url: str) -> str:
    return repo_url.rstrip("/").removesuffix(".git").split("/")[-1] or "project"


def _ensure_signature_db(settings) -> None:
    """Auto-download the signature DB on first run; warn (don't fail) if it can't be fetched."""
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn

    from .dbfetch import _safe_project_count, ensure_db, resolve_source

    if _safe_project_count(settings.db_path) > 0:
        return  # already have a DB with signatures — nothing to do

    if not resolve_source():
        err_console.print(
            "[yellow]no signature DB[/yellow] — git-blob projects will report 'not indexed'. "
            "Set [bold]COMMIPISTE_DB_URL[/bold] to a prebuilt DB, or build one with "
            "[bold]CommiPiste index <name>[/bold]. (Active-probe apps work with --active, no DB.)"
        )
        return

    with Progress(
        TextColumn("[dim]downloading signature DB[/dim]"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=err_console,
        transient=True,
    ) as prog:
        task = prog.add_task("fetch", total=None)
        ok = ensure_db(
            settings,
            log=lambda m: err_console.print(f"[dim]{m}[/dim]"),
            progress=lambda done, total: prog.update(task, completed=done, total=total),
        )
    if not ok:
        err_console.print(
            "[yellow]could not download the signature DB[/yellow] — continuing without it "
            "(git-blob projects will report 'not indexed'; --active still works)."
        )


# --------------------------------------------------------------------------- #
# interactive-update                                                            #
# --------------------------------------------------------------------------- #


@app.command("interactive-update")
def interactive_update_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Assume yes to confirmations."),
    download: bool = typer.Option(
        False, "--download", help="Non-interactively download the prebuilt DB if a newer one exists."
    ),
    check: bool = typer.Option(
        False, "--check", help="Only report whether a newer DB is available (exit 1 if so); no changes."
    ),
) -> None:
    """Interactively check for a newer signature DB and download or rebuild it."""
    from .update import interactive_update

    settings = get_settings()
    raise typer.Exit(
        interactive_update(
            settings, load_registry(settings), assume_yes=yes, download=download, check=check
        )
    )


# --------------------------------------------------------------------------- #
# index                                                                        #
# --------------------------------------------------------------------------- #


@app.command()
def index(
    target: str = typer.Argument(..., help="Registry project name OR a git repository URL."),
    public_path: list[str] = typer.Option(
        None, "--public-path", "-p", help="Public dir(s) to index (repeatable). Overrides config."
    ),
    name: Optional[str] = typer.Option(None, "--name", help="Project name for an ad-hoc repo URL."),
    update: bool = typer.Option(False, "--update", help="Fetch and index only new refs."),
    tags_only: bool = typer.Option(
        False, "--tags-only", help="Index releases only (bounded; for huge repos)."
    ),
    max_files: int = typer.Option(
        2000, "--max-files", help="Keep only the N most discriminating files (0 = unlimited)."
    ),
) -> None:
    """Build or refresh the signature database for a project."""
    settings = get_settings()
    registry = load_registry(settings)

    project = registry.get(target)
    if project is None:
        if "://" not in target and "@" not in target:
            err_console.print(
                f"[red]'{target}' is not a known project and not a repo URL.[/red] "
                f"Known: {', '.join(registry.names()) or '(none)'}"
            )
            raise typer.Exit(1)
        project = Project(
            name=name or _derive_name(target),
            repo_url=target,
            public_paths=list(public_path or []),
        )

    async def run() -> None:
        stats = await _index_project(
            project,
            settings=settings,
            public_paths=list(public_path) if public_path else None,
            update=update,
            tags_only=tags_only,
            max_paths=(max_files or None),
            progress=lambda m: console.print(f"[dim]· {m}[/dim]"),
        )
        console.print(
            f"[green]indexed[/green] {stats.project}: "
            f"paths={stats.public_paths} refs(+{stats.refs_indexed}/skip {stats.refs_skipped}) "
            f"db={stats.stats}"
        )

    asyncio.run(run())


# --------------------------------------------------------------------------- #
# scan                                                                         #
# --------------------------------------------------------------------------- #


@app.command()
def scan(
    url: Optional[str] = typer.Argument(None, help="Target URL (omit when using --targets)."),
    path: Optional[str] = typer.Option(None, "--path", help="Sub-path of the app on the host."),
    software: Optional[str] = typer.Option(
        None, "--software", "-s", help="Force a project, bypassing auto-detection."
    ),
    targets: Optional[Path] = typer.Option(
        None, "--targets", help="File with one target URL per line (batch scan)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a human report."),
    details: bool = typer.Option(
        False, "--details", help="Show per-file discrepancies in the human report."
    ),
    no_dependents: bool = typer.Option(False, "--no-dependents", help="Skip dependent projects."),
    autoindex: bool = typer.Option(
        False,
        "--autoindex",
        help="If the detected software isn't indexed yet, clone its repo and index release tags "
        "on the fly, then fingerprint. For software not in the registry, also pass --repo.",
    ),
    repo: Optional[str] = typer.Option(
        None, "--repo", help="Git URL for --autoindex when the target isn't in the registry."
    ),
    name: Optional[str] = typer.Option(
        None, "--name", help="Name for the --repo project (default: derived from the repo URL)."
    ),
    public: Optional[str] = typer.Option(
        None, "--public", help="Comma-separated public dirs for --repo (default: auto-detected "
        "by probing the repo for known public-dir names)."
    ),
    cpe: Optional[str] = typer.Option(
        None, "--cpe", help="CPE 2.3 prefix for the --repo project, to enable CVE lookup."
    ),
    active: bool = typer.Option(
        False,
        "--active/--no-active",
        help="Active probing: query endpoints to read versions of build-artifact apps (e.g. "
        "Mattermost X-Version-Id). Off by default; opt-in because it hits non-static endpoints.",
    ),
    cve: bool = typer.Option(
        True,
        "--cve/--no-cve",
        help="Look up known vulnerabilities (NVD + OSV; online). On by default; --no-cve to skip.",
    ),
    cve_source: str = typer.Option(
        "default",
        "--cve-source",
        help="Vulnerability source(s): default (cvedb+osv, fast) | nvd | cvedb | osv | both | all. "
        "NVD is opt-in (slow, rate-limited).",
    ),
    report: Optional[Path] = typer.Option(
        None, "--report", help="Write an interactive HTML report to this path."
    ),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Do not verify TLS certs."),
    concurrency: int = typer.Option(8, "--concurrency", "-c", help="Concurrent fetches per host."),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print every operation (files fetched/fingerprinted)."
    ),
) -> None:
    """Scan one or many targets and identify the running software's commit."""
    from .detector.scan import scan_target  # deferred: pulls httpx

    settings = get_settings()
    registry = load_registry(settings)

    url_list: list[str] = []
    if targets:
        url_list = [ln.strip() for ln in targets.read_text().splitlines() if ln.strip()]
    elif url:
        url_list = [url]
    else:
        err_console.print("[red]provide a URL or --targets file[/red]")
        raise typer.Exit(1)

    # First run: if there's no signature DB yet, auto-download a prebuilt one (GitHub Release asset
    # by default; override with COMMIPISTE_DB_URL). Degrades gracefully if nothing is configured
    # or the download fails — active-probe apps still work, the rest report "not indexed".
    _ensure_signature_db(settings)

    progress = (lambda m: console.print(f"[dim]{m}[/dim]")) if verbose else None

    async def run() -> list:
        from .storage import open_storage

        store = await open_storage(settings.db_path)
        try:
            sem = asyncio.Semaphore(max(1, concurrency))

            async def one(u: str):
                async with sem:
                    return await scan_target(
                        u,
                        path=path,
                        software=software,
                        settings=settings,
                        storage=store,
                        registry=registry,
                        with_dependents=not no_dependents,
                        active_probe=active,
                        autoindex=autoindex,
                        repo_url=repo,
                        adhoc_name=name,
                        adhoc_public=[p.strip() for p in public.split(",") if p.strip()] if public else None,
                        adhoc_cpe=cpe,
                        concurrency=concurrency,
                        verify_tls=not insecure,
                        progress=progress,
                    )

            results = await asyncio.gather(*(one(u) for u in url_list))
        finally:
            await store.close()

        if cve:
            from .vuln import enrich_results

            srcs = {
                "default": ("cvedb", "osv"), "nvd": ("nvd",), "osv": ("osv",), "cvedb": ("cvedb",),
                "both": ("nvd", "osv"), "all": ("nvd", "cvedb", "osv"),
            }.get(cve_source.lower(), ("cvedb", "osv"))
            if verbose:
                console.print(f"[dim]looking up vulnerabilities ({', '.join(srcs)})…[/dim]")
            await enrich_results(list(results), registry, sources=srcs)

        return list(results)

    # Run the scan (+CVE) under a self-erasing spinner unless -v (which streams its own progress), so
    # a multi-second scan isn't a silent hang. Output is printed AFTER the spinner stops, so the live
    # spinner never collides with the report/JSON.
    if verbose:
        results = asyncio.run(run())
    else:
        label = url_list[0] if len(url_list) == 1 else f"{len(url_list)} targets"
        with err_console.status(f"scanning {label}…", spinner="dots"):
            results = asyncio.run(run())

    if report:
        from .report_html import render_html

        report.write_text(render_html(results), encoding="utf-8")
        console.print(f"[green]report[/green] written to {report}")

    if as_json:
        if len(results) == 1:
            console.print_json(to_json(results[0]))
        else:
            console.print_json("[" + ",".join(r.to_json(indent=0) for r in results) + "]")
    elif len(results) == 1:
        print_human(results[0], console, show_discrepancies=details)
    else:
        print_batch_summary(results, console)


# --------------------------------------------------------------------------- #
# registry                                                                     #
# --------------------------------------------------------------------------- #


@registry_app.command("list")
def registry_list() -> None:
    """List known project definitions."""
    registry = load_registry(get_settings())
    if not registry.names():
        console.print("[dim](no projects)[/dim]")
        return
    for p in registry.all():
        scope = "local" if p.is_local else "builtin"
        console.print(f"{p.name}  [dim]({scope})[/dim]  {p.repo_url}")


@registry_app.command("add")
def registry_add(
    yaml_path: Path = typer.Argument(..., help="Project-definition YAML to add to the local registry."),
) -> None:
    """Add a user/private project definition to the local registry."""
    project = add_local_project(yaml_path, get_settings())
    console.print(f"[green]added[/green] local project '{project.name}'")


if __name__ == "__main__":
    app()
