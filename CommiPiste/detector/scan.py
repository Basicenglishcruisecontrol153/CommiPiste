"""Orchestrate scanning a target: detect -> fetch -> match -> findings."""

from __future__ import annotations

from typing import Callable, Optional

from ..config import Settings, get_settings
from ..models import Finding, Project, ScanResult
from ..registry import Registry, load_registry
from ..storage import Storage, open_storage
from ..storage.base import ProjectMeta
from .banner import detect_software
from .fetcher import fetch_files, make_client
from .matcher import match_project

# How many discriminator files to probe initially, and how many more on a second pass if the
# first pass leaves several candidate commits.
_PROBE_ROUND1 = 25
_PROBE_ROUND2 = 75


def _normalize_url(url: str) -> str:
    """Default a bare host to https:// — httpx can't fetch a scheme-less URL (it has no host), so
    `scan www.example.org` would otherwise silently find nothing."""
    u = url.strip()
    return u if "://" in u else "https://" + u


def _adhoc_project(
    repo_url: str | None, name: str | None = None,
    public: list[str] | None = None, cpe: str | None = None,
) -> Project | None:
    """Build a throwaway Project for indexing a target unknown to the registry. `public` may be
    empty — autoindex then probes the repo for known public-dir names."""
    if not repo_url:
        return None
    name = name or repo_url.rstrip("/").removesuffix(".git").split("/")[-1].lower()
    return Project(
        name=name, repo_url=repo_url, public_paths=public or [], cpe=cpe, is_local=True
    )


def _persist_local_project(project: Project, paths: list[str], settings) -> None:
    """Save an autoindexed ad-hoc project to the local registry so a later plain
    `scan <url>` knows it — fingerprint detection then identifies it without a banner."""
    import yaml

    settings.ensure_dirs()
    dest = settings.local_registry_dir / f"{project.name}.yaml"
    if dest.exists():
        return
    data = {"name": project.name, "repo_url": project.repo_url, "public_paths": paths}
    if project.cpe:
        data["cpe"] = project.cpe
    dest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _known_public_dirs(registry: Registry) -> list[str]:
    """Distinct public-dir names across the registry, most common first — the candidate set probed
    against a repo when the user didn't name its public dirs (e.g. js, themes, css, images, ...)."""
    from collections import Counter

    c: Counter[str] = Counter()
    for p in registry.all():
        for path in p.public_paths:
            top = path.strip("/").split("/")[0]
            if top:
                c[top] += 1
    return [d for d, _ in c.most_common()]


async def _ensure_indexed(
    store, project: Project, settings, registry: Registry, progress: ProgressCb
) -> ProjectMeta | None:
    """Index the project's release tags into the live DB (tags-only) and return its fresh meta.

    If the project has no configured public_paths (ad-hoc target), probe the cloned repo's
    top-level dirs against the registry's known public-dir names and index those.
    """
    from ..indexer.builder import index_project
    from ..indexer.repo import clone_or_open

    paths = project.public_paths
    if not paths:
        repo = await clone_or_open(project.repo_url, settings.repos_dir)  # cached for index_project
        present = set(await repo.top_dirs())
        paths = [d for d in _known_public_dirs(registry) if d in present]
        if not paths:
            raise ValueError("could not auto-detect public dirs; pass --public <dir,dir>")
        _log(progress, f"[{project.name}] auto-detected public dirs: {', '.join(paths)}")

    _log(progress, f"[{project.name}] autoindex: indexing release tags from {project.repo_url}")
    await index_project(
        project, settings=settings, storage=store, public_paths=paths, tags_only=True,
        progress=lambda m: _log(progress, f"  [{project.name}] {m}"),
    )
    if project.is_local:  # ad-hoc target: remember it so a later plain scan can detect it
        _persist_local_project(project, paths, settings)
    return await store.get_project(project.name)


async def _detect_by_fingerprint(
    store, client, url: str, path: str | None, registry: Registry,
    concurrency: int, progress: ProgressCb,
) -> list[tuple[Project, str]]:
    """Identify banner-less indexed projects by fetching a few discriminator files and checking for
    a hash match. Runs only as a fallback when banner detection found nothing — so autoindexed
    projects (which have no banner) are still recognised on a later plain `scan <url>`.

    ponytail: O(banner-less projects) probes, and the matched project is re-fetched by the main
    scan loop. Fine for a handful of local projects; build a content-hash->project index if the
    local registry ever grows large enough to make this the bottleneck."""
    out: list[tuple[Project, str]] = []
    for project in registry.all():
        b = project.banners
        if b.paths or b.headers or b.body_regex:
            continue  # has banner signals; would have matched already if present
        meta = await store.get_project(project.name)
        if meta is None:
            continue
        probe = await _probe_paths(store, project, meta.id, 8)
        if not probe:
            continue
        outcome = await fetch_files(client, url, probe, path=path, concurrency=concurrency)
        if not outcome.hashes:
            continue
        finding = await match_project(
            store, meta, project.name, outcome.hashes, detected_by="fingerprint",
            missing=outcome.missing, anchors=set(project.probe_files), alt_hashes=outcome.alt_hashes,
        )
        if finding.confidence.files_matched > 0:
            _log(progress, f"[{project.name}] detected by fingerprint")
            out.append((project, "fingerprint"))
    return out

# Optional verbose progress sink: receives human-readable operation lines.
ProgressCb = Optional[Callable[[str], None]]


def _log(progress: ProgressCb, msg: str) -> None:
    if progress is not None:
        progress(msg)


def _fetch_logger(progress: ProgressCb, project_name: str):
    """Build an on_fetch callback that narrates each downloaded/fingerprinted file."""
    if progress is None:
        return None

    def on_fetch(rel: str, kind: str, detail: str) -> None:
        if kind == "fingerprint":
            progress(f"  [{project_name}] fingerprint {rel} = {detail[:12]}")
        elif kind == "miss":
            progress(f"  [{project_name}] skip       {rel} ({detail})")
        else:
            progress(f"  [{project_name}] error      {rel} ({detail})")

    return on_fetch


async def _probe_paths(store: Storage, project: Project, project_id: int, limit: int) -> list[str]:
    """Probe set = configured probe_files plus top discriminators, restricted to indexed paths."""
    known = await store.indexed_paths(project_id)
    discriminators = await store.top_discriminators(project_id, limit)
    ordered: list[str] = []
    seen: set[str] = set()
    for p in list(project.probe_files) + discriminators:
        if p in known and p not in seen:
            ordered.append(p)
            seen.add(p)
    return ordered


async def _scan_one_project(
    store: Storage,
    client,
    url: str,
    path: str | None,
    project: Project,
    meta: ProjectMeta,
    detected_by: str,
    concurrency: int,
    progress: ProgressCb = None,
) -> Finding:
    on_fetch = _fetch_logger(progress, project.name)

    probe = await _probe_paths(store, project, meta.id, _PROBE_ROUND1)
    _log(progress, f"[{project.name}] probing {len(probe)} files (round 1)")
    outcome = await fetch_files(
        client, url, probe, path=path, concurrency=concurrency, on_fetch=on_fetch
    )
    finding = await match_project(
        store, meta, project.name, outcome.hashes,
        detected_by=detected_by, missing=outcome.missing,
        anchors=set(project.probe_files), alt_hashes=outcome.alt_hashes,
    )

    # Adaptive second pass: fetch more discriminators if the commit is not yet pinned down.
    if not finding.confidence.exact and finding.confidence.candidate_count != 1:
        extra = [p for p in await _probe_paths(store, project, meta.id, _PROBE_ROUND2)
                 if p not in outcome.hashes and p not in outcome.missing]
        if extra:
            _log(progress, f"[{project.name}] probing {len(extra)} more files (round 2)")
            more = await fetch_files(
                client, url, extra, path=path, concurrency=concurrency, on_fetch=on_fetch
            )
            outcome.hashes.update(more.hashes)
            outcome.alt_hashes.update(more.alt_hashes)
            outcome.missing.extend(more.missing)
            finding = await match_project(
                store, meta, project.name, outcome.hashes,
                detected_by=detected_by, missing=outcome.missing,
                anchors=set(project.probe_files), alt_hashes=outcome.alt_hashes,
            )
    _log(
        progress,
        f"[{project.name}] matched {finding.confidence.files_matched}/"
        f"{finding.confidence.files_probed} -> "
        f"{finding.version or finding.commit_sha or 'no match'}",
    )
    return finding


async def scan_target(
    url: str,
    *,
    path: str | None = None,
    software: str | None = None,
    settings: Settings | None = None,
    storage: Storage | None = None,
    registry: Registry | None = None,
    with_dependents: bool = True,
    active_probe: bool = False,
    autoindex: bool = False,
    repo_url: str | None = None,
    adhoc_name: str | None = None,
    adhoc_public: list[str] | None = None,
    adhoc_cpe: str | None = None,
    timeout: float = 10.0,
    concurrency: int = 8,
    verify_tls: bool = True,
    progress: ProgressCb = None,
) -> ScanResult:
    """Scan a single target URL and identify the running software's commit(s).

    `software` forces a specific project, bypassing auto-detection. Otherwise every registered
    project's banner is checked against the target. `progress`, if given, receives a line per
    operation (detection, each file fetched/fingerprinted) for verbose output.
    """
    settings = settings or get_settings()
    registry = registry or load_registry(settings)

    url = _normalize_url(url)
    own_storage = storage is None
    store = storage or await open_storage(settings.db_path)
    result = ScanResult(url=url, path=path)
    client = make_client(timeout=timeout, verify=verify_tls)
    try:
        # Resolve which projects to check.
        # An ad-hoc project (--repo, for software not in the registry); registered so CVE
        # enrichment can resolve its cpe too. public_paths auto-detected at index time if omitted.
        adhoc = _adhoc_project(repo_url, name=adhoc_name, public=adhoc_public, cpe=adhoc_cpe)
        if adhoc is not None:
            registry._projects[adhoc.name] = adhoc

        if software:
            project = registry.get(software) or (adhoc if adhoc and adhoc.name == software else None)
            if project is None:
                hint = " (pass --repo to autoindex it)" if autoindex else ""
                result.error = f"unknown software '{software}'; not in registry{hint}"
                return result
            _log(progress, f"{url}: software forced to '{project.name}'")
            detected = [(project, "autoindex" if project is adhoc else "user")]
        else:
            _log(progress, f"{url}: detecting software by banner ({len(registry.all())} known)")
            names = await detect_software(client, url, registry.all(), path=path)
            detected = [(registry.get(n), "banner") for n in names if registry.get(n)]
            if not detected:
                # No banner match — fall back to fingerprinting banner-less indexed projects.
                detected = await _detect_by_fingerprint(
                    store, client, url, path, registry, concurrency, progress
                )
            if not detected and autoindex and adhoc is not None:
                detected = [(adhoc, "autoindex")]
            if not detected:
                result.error = "no known software detected by banner" + (
                    "; pass --repo <git-url> with --autoindex to index an unknown project"
                    if autoindex else ""
                )
                return result
            _log(progress, f"{url}: detected {', '.join(p.name for p, _ in detected)}")

        for project, detected_by in detected:
            # Build-artifact apps that expose a version at an endpoint use active probing (opt-in).
            if project.version_probe is not None:
                if not active_probe:
                    _log(progress, f"[{project.name}] needs --active to read the version")
                    result.findings.append(
                        Finding(
                            software=project.name,
                            detected_by=detected_by,
                            needs_active_probe=True,
                        )
                    )
                    continue
                from .active import probe_version

                finding = await probe_version(client, url, path, project, detected_by="active")
                _log(progress, f"[{project.name}] active probe -> {finding.version or 'no version'}")
                result.findings.append(finding)
                continue

            meta = await store.get_project(project.name)
            if meta is None and autoindex:
                try:
                    meta = await _ensure_indexed(store, project, settings, registry, progress)
                except Exception as e:  # clone/index failure shouldn't abort the whole scan
                    _log(progress, f"[{project.name}] autoindex failed: {e}")
            if meta is None:
                # Detected but never indexed: report it so the user knows to run `index`
                # (or re-run with --autoindex if the build did not succeed).
                _log(progress, f"[{project.name}] not indexed — skipping fingerprint")
                result.findings.append(
                    Finding(software=project.name, detected_by=detected_by, indexed=False)
                )
                continue
            finding = await _scan_one_project(
                store, client, url, path, project, meta, detected_by, concurrency, progress
            )
            result.findings.append(finding)

            if with_dependents:
                from .dependents import scan_dependents

                result.findings.extend(
                    await scan_dependents(
                        store, client, url, path, project, registry, concurrency, progress
                    )
                )

        return result
    finally:
        await client.aclose()
        if own_storage:
            await store.close()
