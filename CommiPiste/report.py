"""Render scan results: machine-readable JSON and a human-readable report."""

from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Finding, ScanResult

NVD_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"


def nvd_key_hint(error: str | None) -> str | None:
    """Actionable hint for NVD failures (rate limit / 503 / timeout) when no API key is set."""
    if not error or "NVD" not in error or os.environ.get("NVD_API_KEY"):
        return None
    return f"fix: get a free NVD API key, then `export NVD_API_KEY=<key>` — {NVD_KEY_URL}"


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Machine-readable output for pipeline integration."""
    return result.to_json(indent=indent)


def candidate_commit_urls(f: Finding) -> list[str]:
    """Source-host links for each candidate commit (for manual verification of a non-exact match).

    Derived by substituting each candidate sha into the headline commit URL (same repo/host shape).
    """
    if not f.commit_url or not f.commit_sha or not f.commit_range:
        return []
    return [f.commit_url.replace(f.commit_sha, sha) for sha in f.commit_range]


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")


def _finding_lines(f: Finding, show_discrepancies: bool = False) -> list[str]:
    lines: list[str] = []
    head = f"[bold]{f.software}[/bold] (detected by {f.detected_by})"
    lines.append(head)
    if f.needs_active_probe:
        lines.append(
            "  [yellow]active probing required — re-run with --active to get the version for "
            "this platform (bundled assets were detected)[/yellow]"
        )
        return lines
    if f.commit_sha:
        if f.commit_inferred:
            marker = "inferred from version tag — approximate, may differ if patched/forked"
        elif f.confidence.exact:
            marker = "exact"
        else:
            marker = "best candidate"
        lines.append(f"  [bold]commit:[/bold] {f.commit_sha[:12]}  ({marker})")
        if f.commit_url:
            lines.append(f"  [bold]github:[/bold] {f.commit_url}")
    if f.version:
        label = "version" if f.match_basis == "exact" else f"version (by {f.match_basis})"
        lines.append(f"  [bold]{label}:[/bold] {f.version}")
    if f.version_range:
        lines.append(f"  [bold]evidence range:[/bold] {f.version_range}")
    # When the commit is not pinned to one, show which versions remain in play and the files that
    # uniquely point at exactly those versions (the discriminating evidence).
    if f.candidate_versions:
        shown = ", ".join(f.candidate_versions[:8])
        more = "" if len(f.candidate_versions) <= 8 else f" (+{len(f.candidate_versions) - 8} more)"
        lines.append(f"  [bold]candidate versions:[/bold] {shown}{more}")
        if f.key_files:
            lines.append("  [bold]key files[/bold] (match only these versions):")
            for kf in f.key_files:
                lines.append(f"    - {kf}")
        cand_urls = candidate_commit_urls(f)
        if cand_urls:
            lines.append("  [bold]candidate commits[/bold] (verify on the source host):")
            for url in cand_urls[:8]:
                lines.append(f"    - {url}")
            if len(cand_urls) > 8:
                lines.append(f"    ... (+{len(cand_urls) - 8} more)")
    c = f.confidence
    lines.append(
        f"  [bold]confidence:[/bold] {c.label}  "
        f"(matched {c.files_matched}/{c.files_probed}, score {c.score:.2f})"
    )
    if f.modified:
        lines.append("  [yellow]modified deployment: some files differ from the matched version[/yellow]")
    if not f.commit_sha and c.files_probed == 0 and not f.version:
        if f.detected_by == "active":
            lines.append("  [dim]active probe found no version at the configured endpoint[/dim]")
        elif not f.indexed:
            lines.append(
                "  [dim]not indexed — set COMMIPISTE_DB_URL to a prebuilt DB, "
                "or build this project with `CommiPiste index <name>`[/dim]"
            )
        else:
            lines.append(
                "  [dim]no probe files served by the target — asset paths differ or assets are "
                "generated/bundled[/dim]"
            )
    # Vulnerability summary (only when --cve enrichment ran).
    v = f.vulnerabilities
    if v is not None:
        via_parts = []
        if "NVD" in v.sources:
            via_parts.append(f"NVD: {_plural(v.versions_checked or 1, 'version')}")
        if "OSV" in v.sources:
            via_parts.append(f"OSV: {_plural(v.commits_checked or 1, 'candidate commit')}")
        via = f" [dim](via {', '.join(via_parts)})[/dim]" if via_parts else ""
        if v.total:
            color = "red" if v.by_severity.get("CRITICAL") or v.by_severity.get("HIGH") else "yellow"
            lines.append(f"  [{color}][bold]vulnerabilities:[/bold] {v.headline}[/{color}]{via}")
            for cve in v.top[:5]:
                sev = (cve.severity or "?")
                score = f" {cve.cvss_score}" if cve.cvss_score is not None else ""
                src = f"  [dim]{'/'.join(cve.sources)}[/dim]" if cve.sources else ""
                lines.append(f"    - {cve.cve_id} [{sev}{score}]  {cve.url}{src}")
            if v.nvd_url:
                lines.append(f"    [bold]all:[/bold] {v.nvd_url}")
            if v.error:
                lines.append(f"    [dim]note: {v.error}[/dim]")
                hint = nvd_key_hint(v.error)
                if hint:
                    lines.append(f"    [yellow]{hint}[/yellow]")
        elif v.error:
            lines.append(f"  [dim]vulnerability lookup: {v.error}[/dim]")
            hint = nvd_key_hint(v.error)
            if hint:
                lines.append(f"  [yellow]{hint}[/yellow]")
        else:
            lines.append(f"  [green]no known vulnerabilities for this version[/green]{via}")
    # Discrepancy details are hidden by default (use --details); JSON output always keeps them.
    if show_discrepancies and f.discrepancies:
        lines.append(f"  [bold]discrepancies:[/bold] {len(f.discrepancies)}")
        for d in f.discrepancies[:15]:
            lines.append(f"    - {d.kind}: {d.rel_path}")
        if len(f.discrepancies) > 15:
            lines.append(f"    ... (+{len(f.discrepancies) - 15} more)")
    return lines


def print_human(
    result: ScanResult,
    console: Console | None = None,
    *,
    show_discrepancies: bool = False,
) -> None:
    """Human-readable report. Discrepancy details are shown only when requested."""
    console = console or Console(highlight=False)
    title = f"{result.url}" + (f"  (path: {result.path})" if result.path else "")
    if result.error:
        console.print(Panel(f"[red]{result.error}[/red]", title=title, expand=False))
        return
    if not result.findings:
        console.print(Panel("[dim]no findings[/dim]", title=title, expand=False))
        return
    body: list[str] = []
    for i, f in enumerate(result.findings):
        if i:
            body.append("")
        body.extend(_finding_lines(f, show_discrepancies=show_discrepancies))
    console.print(Panel("\n".join(body), title=title, expand=False))


def print_batch_summary(results: list[ScanResult], console: Console | None = None) -> None:
    """Compact one-row-per-target table for batch scans."""
    console = console or Console(highlight=False)
    table = Table(title="CommiPiste — batch scan")
    table.add_column("target", overflow="fold")
    table.add_column("software")
    table.add_column("commit")
    table.add_column("version")
    table.add_column("confidence")
    for r in results:
        if r.error or not r.findings:
            table.add_row(r.url, "-", "-", "-", r.error or "no findings")
            continue
        for f in r.findings:
            table.add_row(
                r.url,
                f.software,
                (f.commit_sha[:12] if f.commit_sha else "-"),
                f.version or "-",
                f.confidence.label,
            )
    console.print(table)
