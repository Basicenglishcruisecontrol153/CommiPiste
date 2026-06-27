"""WordPress.org SVN-over-HTTP backend (for plugins/themes not mirrored to git).

Every wordpress.org plugin lives at https://plugins.svn.wordpress.org/<slug>/ (themes at
themes.svn.wordpress.org) with a uniform `tags/<version>/` layout, served as browsable HTML — no
`svn` client needed. Unlike git, SVN exposes no blob OIDs, so this backend fetches file *content*
and computes the git blob OID itself (same canonical hash as the git path), letting it slot into the
existing indexer with the same `tags()` / `ls_tree()` interface as :class:`GitRepo`.
"""

from __future__ import annotations

import asyncio
import re

import httpx

from ..hashing import git_blob_hash

PLUGINS_BASE = "https://plugins.svn.wordpress.org"
THEMES_BASE = "https://themes.svn.wordpress.org"
_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
_HREF = re.compile(r'<li>\s*<a\s+href="([^"]+)"', re.I)
_UA = "CommiPiste/0.1 (OSINT fingerprinting)"


class WpOrgRepo:
    """Mirrors the GitRepo interface (tags / ls_tree) over the wordpress.org SVN HTTP listing."""

    def __init__(self, slug: str, base: str = PLUGINS_BASE, concurrency: int = 12) -> None:
        self.slug = slug
        self.base = base.rstrip("/")
        self._sem = asyncio.Semaphore(concurrency)
        self.client = httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, headers={"User-Agent": _UA}
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def tags(self) -> list[str]:
        """Released version strings from the WP.org API, falling back to the SVN tags/ listing."""
        try:
            r = await self.client.get(_API.format(slug=self.slug))
            if r.status_code == 200:
                versions = (r.json() or {}).get("versions") or {}
                vers = [v for v in versions if v and v[0].isdigit()]
                if vers:
                    return vers
        except (httpx.HTTPError, ValueError):
            pass
        dirs, _ = await self._list(f"{self.base}/{self.slug}/tags/")
        return [d.rstrip("/") for d in dirs if d[:1].isdigit()]

    async def _list(self, url: str) -> tuple[list[str], list[str]]:
        """Return (subdir names, file names) from an SVN HTML directory listing."""
        async with self._sem:
            try:
                r = await self.client.get(url if url.endswith("/") else url + "/")
            except httpx.HTTPError:
                return [], []
        if r.status_code != 200:
            return [], []
        names = [n for n in _HREF.findall(r.text) if not n.startswith("../")]
        dirs = [n for n in names if n.endswith("/")]
        files = [n for n in names if not n.endswith("/")]
        return dirs, files

    async def ls_tree(self, version: str, paths: list[str]) -> list[tuple[str, str]]:
        """Recursively list files under `paths` at a version and git-blob-hash each one.

        Returns (rel_path, oid) with rel_path relative to the plugin root (it includes the
        public-path prefix, matching the git backend), so it slots straight into the indexer.
        """
        out: list[tuple[str, str]] = []
        root = f"{self.base}/{self.slug}/tags/{version}/"

        async def walk(rel: str) -> None:
            dirs, files = await self._list(root + rel)
            await asyncio.gather(*(self._hash_file(root + rel + f, rel + f, out) for f in files))
            await asyncio.gather(*(walk(rel + d) for d in dirs))

        await asyncio.gather(*(walk(p.strip("/") + "/") for p in paths))
        return out

    async def _hash_file(self, url: str, rel_path: str, out: list) -> None:
        async with self._sem:
            try:
                r = await self.client.get(url)
            except httpx.HTTPError:
                return
        if r.status_code == 200:
            out.append((rel_path, git_blob_hash(r.content)))
