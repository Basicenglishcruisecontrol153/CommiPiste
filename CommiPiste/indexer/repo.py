"""Repository access via the `git` CLI.

We keep a bare clone per project under the data directory and shell out to `git`. Bare clones avoid
a working tree we never need: every hash comes from `git ls-tree`, never from a checkout.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    pass


@dataclass
class GitRepo:
    """A bare git clone we can query without checking anything out."""

    path: Path

    async def _git(self, *args: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "git",
            f"--git-dir={self.path}",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise GitError(f"git {' '.join(args)} failed: {err.decode(errors='replace').strip()}")
        return out.decode(errors="replace")

    async def fetch(self) -> None:
        """Update refs/tags (incremental indexing)."""
        await self._git("fetch", "--tags", "--force", "--prune", "origin")

    async def tags(self) -> list[str]:
        out = await self._git("tag", "--list")
        return [t.strip() for t in out.splitlines() if t.strip()]

    async def rev_parse(self, ref: str) -> str:
        return (await self._git("rev-parse", ref)).strip()

    async def commit_info(self, ref: str) -> tuple[str, str]:
        """Return (commit_sha, ISO-8601 committed date) for a ref, dereferencing tags."""
        out = (await self._git("log", "-1", "--format=%H|%cI", f"{ref}^{{commit}}")).strip()
        sha, _, date = out.partition("|")
        return sha, date

    async def log_touching(
        self, paths: list[str], since: str | None = None
    ) -> list[tuple[str, str]]:
        """(sha, ISO date) pairs (oldest-first) for commits that change any of `paths`."""
        args = ["log", "--format=%H|%cI", "--reverse"]
        if since:
            args.append(f"{since}..HEAD")
        args.append("--")
        args.extend(paths)
        out = await self._git(*args)
        result: list[tuple[str, str]] = []
        for line in out.splitlines():
            sha, _, date = line.strip().partition("|")
            if sha:
                result.append((sha, date))
        return result

    async def ls_tree(self, ref: str, paths: list[str]) -> list[tuple[str, str]]:
        """Return (rel_path, blob_oid) for every file under `paths` at `ref`.

        The blob OID comes straight from git — no blob content is read or re-hashed.
        """
        args = ["ls-tree", "-r", ref, "--"]
        args.extend(paths)
        out = await self._git(*args)
        files: list[tuple[str, str]] = []
        for line in out.splitlines():
            # format: "<mode> <type> <oid>\t<path>"
            meta, _, rel_path = line.partition("\t")
            if not rel_path:
                continue
            parts = meta.split()
            if len(parts) != 3 or parts[1] != "blob":
                continue  # skip submodules/trees
            files.append((rel_path, parts[2]))
        return files

    async def top_dirs(self, ref: str = "HEAD") -> list[str]:
        """Top-level directory names at `ref` (for autoindex public-dir probing)."""
        out = await self._git("ls-tree", ref)
        dirs: list[str] = []
        for line in out.splitlines():
            meta, _, name = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "tree" and name:
                dirs.append(name.rstrip("/"))
        return dirs


_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(repo_url: str) -> str:
    return _SAFE.sub("_", repo_url.rstrip("/").removesuffix(".git"))


async def clone_or_open(repo_url: str, repos_dir: Path, update: bool = False) -> GitRepo:
    """Clone the repo as a bare mirror if absent, else open it (optionally fetching)."""
    repos_dir.mkdir(parents=True, exist_ok=True)
    dest = repos_dir / (_slug(repo_url) + ".git")
    if dest.exists():
        repo = GitRepo(dest)
        if update:
            await repo.fetch()
        return repo

    # Blobless partial clone: we only ever read blob OIDs from `git ls-tree` and never read blob
    # content, so omitting blobs gives everything indexing needs at a fraction of the size/time.
    # Tree/commit objects (which carry the OIDs) are still fetched in full. Works on GitHub and
    # GitLab; some hosts (older SourceForge git) reject partial clone, so fall back to a full clone.
    async def _clone(*extra: str) -> int:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--bare", *extra, repo_url, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        return proc.returncode, err.decode(errors="replace").strip()

    rc, err = await _clone("--filter=blob:none")
    if rc != 0:
        # Partial clone unsupported by the remote? Retry without the filter (full clone).
        if dest.exists():
            import shutil

            shutil.rmtree(dest, ignore_errors=True)
        rc2, err2 = await _clone()
        if rc2 != 0:
            raise GitError(f"git clone failed: {err2 or err}")
    return GitRepo(dest)
