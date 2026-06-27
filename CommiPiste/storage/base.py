"""Project metadata persisted alongside signatures.

The signature store is SQLite (:class:`CommiPiste.storage.sqlite.SqliteStorage`); this module just
holds :class:`ProjectMeta`, the per-project metadata needed to render results without the registry
YAML being present.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProjectMeta:
    """Minimal project metadata persisted alongside signatures.

    Enough to resolve commit URLs and report results without the registry YAML being present.
    """

    id: int
    name: str
    repo_url: str
    github_commit_url_tpl: str
    kind: str
    parent: Optional[str]

    def commit_url(self, sha: str) -> str:
        return self.github_commit_url_tpl.format(repo_url=self.repo_url.rstrip("/"), sha=sha)

    def file_url(self, sha: str, rel_path: str) -> Optional[str]:
        """Link to one file at a given commit, derived from the commit-URL shape.

        GitHub/most forges use ``/blob/{sha}/{path}``; GitLab uses ``/-/blob/{sha}/{path}``. For
        sources without a blob view in this shape (e.g. wordpress.org SVN), returns None.
        Note: paths are web-root-relative; for projects served from a repo subdir the link omits
        that prefix (best-effort).
        """
        repo = self.repo_url.rstrip("/")
        path = rel_path.lstrip("/")
        tpl = self.github_commit_url_tpl
        if "/-/tree/" in tpl or "/-/commit/" in tpl:  # GitLab
            return f"{repo}/-/blob/{sha}/{path}"
        if "/tree/" in tpl or "/commit/" in tpl:  # GitHub and most other git forges
            return f"{repo}/blob/{sha}/{path}"
        return None
