"""Orchestrate signature-database construction for a project.

Pipeline: clone/fetch -> detect public dir -> collect refs (tags + touching-commits) -> for each
ref `git ls-tree` the public paths and record (rel_path, oid) observations -> recompute
discriminators. Hashes come straight from ls-tree; blob content is never read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from ..config import Settings, get_settings
from ..models import Project
from ..storage import Storage, open_storage
from .repo import clone_or_open
from .walker import collect_refs

ProgressCb = Callable[[str], Awaitable[None] | None]


@dataclass
class IndexStats:
    project: str
    public_paths: list[str]
    refs_indexed: int
    refs_skipped: int
    stats: dict[str, int]


async def _emit(cb: Optional[ProgressCb], msg: str) -> None:
    if cb is None:
        return
    res = cb(msg)
    if hasattr(res, "__await__"):
        await res


async def _ls_public(repo, sha, repo_paths, strip):
    """ls-tree the repo-relative public paths, returning web-root-relative (rel_path, oid).

    `strip` is the repo_subdir prefix to remove so stored paths match served URLs (e.g. phpBB).
    """
    files = await repo.ls_tree(sha, repo_paths)
    if not strip:
        return files
    pre = strip.rstrip("/") + "/"
    return [(p[len(pre):], o) if p.startswith(pre) else (p, o) for p, o in files]


async def _index_full(store, repo, project_id, repo_paths, strip, refs, progress, max_paths):
    """Full index, storing only the most version-discriminating files.

    Pass 1 reads every ref's tree to learn, per path, the set of distinct blob OIDs and how many
    refs contain it. We then keep only discriminating paths:
      - drop files invariant across the whole history (same OID in every ref) — zero info;
      - rank the rest by distinct-OID count (how finely they split the version space) and keep the
        top `max_paths` (None = keep all). We only ever probe ~100 files at scan time, so the long
        tail of weak discriminators is pure storage cost.
    Pass 2 writes observations for kept paths only.
    """
    import sys

    ref_files: list[tuple] = []
    path_oids: dict[str, set[str]] = {}
    path_count: dict[str, int] = {}

    for ref in refs:
        files = await _ls_public(repo, ref.sha, repo_paths, strip)
        if not files:
            continue
        interned = []
        for p, o in files:
            p = sys.intern(p)
            o = sys.intern(o)
            interned.append((p, o))
            path_oids.setdefault(p, set()).add(o)
            path_count[p] = path_count.get(p, 0) + 1
        ref_files.append((ref, interned))

    num_refs = len(ref_files)
    discriminating = [
        p
        for p, oids in path_oids.items()
        if not (len(oids) == 1 and path_count[p] == num_refs)
    ]
    # Most-discriminating first (more distinct OIDs => splits versions more finely).
    discriminating.sort(key=lambda p: (len(path_oids[p]), path_count[p]), reverse=True)
    if max_paths is not None and len(discriminating) > max_paths:
        discriminating = discriminating[:max_paths]
    keep = set(discriminating)
    await _emit(
        progress,
        f"keeping {len(keep)}/{len(path_oids)} paths "
        f"(dropped {len(path_oids) - len(keep)}: invariant + weak discriminators)",
    )

    # Add all refs, then collapse to one entry per (path, oid) carrying its set of ref ids.
    collapsed: dict[tuple[str, str], list[int]] = {}
    indexed = 0
    for ref, files in ref_files:
        ref_id = await store.add_ref(
            project_id, ref.sha, ref.tag, ref.committed_date, ref.is_release
        )
        for p, o in files:
            if p in keep:
                collapsed.setdefault((p, o), []).append(ref_id)
        indexed += 1
        if indexed % 100 == 0:
            await _emit(progress, f"collected {indexed}/{num_refs} refs")

    await _emit(progress, f"writing {len(collapsed)} collapsed signatures")
    await store.record_signatures(
        project_id, [(p, o, ids) for (p, o), ids in collapsed.items()]
    )
    return indexed, len(refs) - num_refs


async def _index_incremental(store, repo, project_id, repo_paths, strip, refs, progress):
    """Index only new refs, reusing the existing discriminating path set.

    New discriminating paths introduced by newer releases are picked up by a full reindex; an
    incremental run records new refs against the paths already known to the project.
    """
    keep = await store.indexed_paths(project_id)
    indexed = skipped = 0
    for ref in refs:
        if await store.ref_exists(project_id, ref.sha):
            skipped += 1
            continue
        files = await _ls_public(repo, ref.sha, repo_paths, strip)
        if not files:
            skipped += 1
            continue
        ref_id = await store.add_ref(
            project_id, ref.sha, ref.tag, ref.committed_date, ref.is_release
        )
        # If the project has no prior paths (first index via --update), keep everything.
        selected = [(p, o) for p, o in files if (not keep or p in keep)]
        await store.append_ref_files(project_id, ref_id, selected)
        indexed += 1
    return indexed, skipped


async def index_project(
    project: Project,
    *,
    settings: Settings | None = None,
    storage: Storage | None = None,
    public_paths: list[str] | None = None,
    update: bool = False,
    tags_only: bool = False,
    max_paths: int | None = 2000,
    progress: Optional[ProgressCb] = None,
) -> IndexStats:
    """Index `project` into the signature DB.

    `public_paths` overrides both the registry definition and heuristics. `update=True`
    fetches new refs and indexes only those not seen yet. `tags_only` indexes releases only
    — bounded and fast for huge repos. `max_paths` caps stored signatures to the N most
    version-discriminating files per project (None = keep all); we only probe ~100 files at scan
    time, so the default keeps matching quality while bounding DB size.
    """
    settings = settings or get_settings()
    settings.ensure_dirs()

    own_storage = storage is None
    store = storage or await open_storage(settings.db_path)
    wporg_repo = None
    try:
        if project.source == "wporg":
            # wordpress.org SVN-over-HTTP: name is the slug, versions come from the WP.org API,
            # public_paths are plugin-root-relative (no clone, no repo_subdir, no touching-commits).
            from .wporg import WpOrgRepo
            from .walker import IndexRef

            await _emit(progress, f"opening wordpress.org source for {project.name}")
            repo = wporg_repo = WpOrgRepo(project.name)
            paths = public_paths or project.public_paths
            strip = ""
            repo_paths = paths
            versions = await repo.tags()
            refs = [IndexRef(sha=v, tag=v, committed_date=None, is_release=True) for v in versions]
            await _emit(progress, f"public paths: {', '.join(paths)} | {len(refs)} versions")
        else:
            await _emit(progress, f"opening repo {project.repo_url}")
            repo = await clone_or_open(project.repo_url, settings.repos_dir, update=update)

            configured = public_paths or project.public_paths
            paths = [p.rstrip("/") for p in configured]
            if not paths:
                raise ValueError(
                    f"no public paths for {project.name}; set public_paths in the registry "
                    f"or pass them explicitly (--public-path)"
                )
            # Map web-root-relative public paths to repo-relative ones (repo_subdir, e.g. phpBB).
            strip = project.repo_subdir.strip("/")
            repo_paths = [f"{strip}/{p}" if strip else p for p in paths]
            await _emit(
                progress,
                f"public paths: {', '.join(paths)}" + (f" (under {strip}/)" if strip else ""),
            )
            refs = await collect_refs(repo, repo_paths, tags_only=tags_only)
            await _emit(progress, f"{len(refs)} candidate refs")

        project_id = await store.upsert_project(
            name=project.name,
            repo_url=project.repo_url,
            github_commit_url_tpl=project.commit_url_tpl,
            kind=project.kind.value,
            parent=project.parent,
        )

        if update and project.source != "wporg":
            indexed, skipped = await _index_incremental(
                store, repo, project_id, repo_paths, strip, refs, progress
            )
        else:
            indexed, skipped = await _index_full(
                store, repo, project_id, repo_paths, strip, refs, progress, max_paths
            )

        await _emit(progress, "recomputing discriminators")
        await store.recompute_discriminators(project_id)

        stats = await store.project_stats(project_id)
        return IndexStats(
            project=project.name,
            public_paths=paths,
            refs_indexed=indexed,
            refs_skipped=skipped,
            stats=stats,
        )
    finally:
        if wporg_repo is not None:
            await wporg_repo.aclose()
        if own_storage:
            await store.close()
