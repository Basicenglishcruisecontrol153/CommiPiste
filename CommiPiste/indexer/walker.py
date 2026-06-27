"""Select the points in history to index.

Strategy (agreed): index **tags/releases plus the commits that change the public dir** between them
— not every commit (re-hashing every file at every commit is infeasible on large repos like
Nextcloud with 100k+ commits). Tags give clean version anchors; touching-commits capture the
inter-release states where served files actually change.
"""

from __future__ import annotations

from dataclasses import dataclass

from .repo import GitRepo


@dataclass
class IndexRef:
    sha: str
    tag: str | None
    committed_date: str | None
    is_release: bool


async def collect_refs(
    repo: GitRepo,
    public_paths: list[str],
    since: str | None = None,
    tags_only: bool = False,
) -> list[IndexRef]:
    """Return the de-duplicated set of refs to index.

    `since` (a sha) limits touching-commits to those after it, for incremental updates;
    tags are always re-scanned so newly created tags are picked up. `tags_only` skips touching
    commits entirely — bounded and fast, the right choice for huge repos where the public dir
    changes on nearly every commit.
    """
    by_sha: dict[str, IndexRef] = {}

    # Tags / releases.
    for tag in await repo.tags():
        try:
            sha, date = await repo.commit_info(tag)
        except Exception:
            continue  # skip broken/dangling tags
        existing = by_sha.get(sha)
        if existing:
            existing.tag = existing.tag or tag
            existing.is_release = True
            existing.committed_date = existing.committed_date or date
        else:
            by_sha[sha] = IndexRef(sha=sha, tag=tag, committed_date=date, is_release=True)

    # Commits that change the public dir (unless tags-only).
    if not tags_only:
        for sha, date in await repo.log_touching(public_paths, since=since):
            if sha not in by_sha:
                by_sha[sha] = IndexRef(sha=sha, tag=None, committed_date=date, is_release=False)

    # Stable order: oldest first by date, then sha.
    return sorted(by_sha.values(), key=lambda r: (r.committed_date or "", r.sha))
