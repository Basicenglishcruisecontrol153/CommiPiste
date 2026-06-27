"""Active version probing (opt-in via `--active`).

For build-artifact apps whose served assets don't match git blobs (bundled/minified/content-hashed),
but which expose their version at an endpoint. Reads the version out of a response header or body
via the project's `version_probe` regex. Because it queries dedicated (often API) endpoints rather
than fetching public static files, it is opt-in.

Returns a :class:`Finding` (with `detected_by="active"`); `version` is None if no endpoint yielded a
match, so the caller can report "active probe found no version".
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import httpx

from ..models import Finding, Project
from ..vuln.nvd import normalize_version
from .fetcher import _base


async def resolve_tag_commit(repo_url: str, version: str) -> str | None:
    """Best-effort: the commit SHA of the release tag matching `version` (via `git ls-remote`).

    Inexact by nature — it returns the tag's commit, not the actually-deployed one (the deployment
    may be patched/forked). No clone; one network call. Returns None if git/network fails or no tag
    matches.
    """
    clean = normalize_version(version)
    if not clean:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "ls-remote", "--tags", repo_url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
    except (OSError, asyncio.TimeoutError):
        return None
    match: str | None = None
    for line in out.decode(errors="replace").splitlines():
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/"):
            continue
        tag = ref[len("refs/tags/"):].removesuffix("^{}")
        if normalize_version(tag) == clean:
            match = sha.strip()  # prefer the peeled (^{}) line if present — it comes last
    return match


async def probe_version(
    client: httpx.AsyncClient,
    url: str,
    path: str | None,
    project: Project,
    *,
    detected_by: str = "active",
) -> Finding:
    """Query the project's version_probe endpoints and extract the version. Always returns a Finding."""
    finding = Finding(software=project.name, detected_by=detected_by)
    spec = project.version_probe
    if spec is None:
        return finding

    base = _base(url, path)
    for ep in spec.paths or [""]:
        target = urljoin(base, ep.lstrip("/")) if ep else base
        try:
            if spec.method.upper() == "POST":
                resp = await client.post(
                    target, content=spec.body, follow_redirects=True,
                    headers={"Content-Type": spec.content_type or "application/json"},
                )
            else:
                resp = await client.get(target, follow_redirects=True)
        except httpx.HTTPError:
            continue
        if spec.header:
            # A version header (X-Jenkins, X-Version-Id, …) is present regardless of status —
            # e.g. Jenkins root is 403 but still carries X-Jenkins. Don't gate on 200 here.
            source = resp.headers.get(spec.header)
        else:
            if resp.status_code != 200:
                continue
            source = resp.text
        if not source:
            continue
        m = re.search(spec.regex, source)
        if not m:
            continue
        finding.version = spec.version_template.format(*m.groups()) if spec.version_template else m.group(1)
        if spec.commit_regex:
            cm = re.search(spec.commit_regex, source)
            if cm:
                finding.commit_sha = cm.group(1)  # observed commit
                finding.commit_url = project.commit_url(cm.group(1))
        # No observed commit but the version is known: optionally infer the commit from the tag.
        if not finding.commit_sha and spec.resolve_commit_from_tags:
            sha = await resolve_tag_commit(project.repo_url, finding.version)
            if sha:
                finding.commit_sha = sha
                finding.commit_url = project.commit_url(sha)
                finding.commit_inferred = True
        # The exposed version is authoritative; mark it identified (not a git-blob commit match).
        c = finding.confidence
        c.files_probed = c.files_matched = 1
        c.score = 1.0
        c.exact = True
        return finding
    return finding  # version stays None: probed but nothing matched
