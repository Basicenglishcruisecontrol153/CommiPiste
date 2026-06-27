"""Fetch static files from a target and hash them.

Downloads only the requested relative paths, with bounded concurrency and a per-request timeout to
keep load on the target low. Each fetched body is hashed with :func:`git_blob_hash`, so the
resulting OID matches the index directly.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin

import httpx

from ..hashing import git_blob_hash_variants

# Per-file event callback: (rel_path, kind, detail) where kind is "fingerprint" | "miss" | "error".
FetchEvent = Optional[Callable[[str, str, str], None]]

# A current desktop-Chrome UA: lightweight non-browser UAs get CAPTCHA'd/blocked by Cloudflare/WAFs,
# which would look like "not fingerprintable" when the assets are really there.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)

# Repo directories that are commonly the deployed web root (so their name does not appear in served
# URLs). When an indexed path starts with one of these, we also try the URL with the prefix
# stripped — e.g. an asset stored as "public/theme/x.css" (Moodle/Redmine layout) is served at
# "/theme/x.css". Matching still keys on the original stored path; only the fetch URL is adjusted,
# so deployment-layout differences need no re-indexing.
_WEBROOT_PREFIXES = (
    "public/",
    "htdocs/",
    "html/",
    "public_html/",
    "web/",
    "www/",
    "upload/",
)


def served_candidates(rel: str) -> list[str]:
    """URL-relative paths to try for an indexed path: itself, then web-root-prefix-stripped."""
    cands = [rel]
    for pre in _WEBROOT_PREFIXES:
        if rel.startswith(pre) and len(rel) > len(pre):
            cands.append(rel[len(pre):])
    return cands


@dataclass
class FetchOutcome:
    """Result of probing a set of relative paths."""

    hashes: dict[str, str] = field(default_factory=dict)  # rel_path -> oid served (HTTP 200 only)
    # rel_path -> additional OIDs to also accept (e.g. CRLF→LF normalized); tried if `hashes` misses.
    alt_hashes: dict[str, list[str]] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)  # 404 / non-200
    errors: dict[str, str] = field(default_factory=dict)  # rel_path -> error text


def _base(url: str, path: str | None) -> str:
    base = url if url.endswith("/") else url + "/"
    if path:
        base = urljoin(base, path.lstrip("/"))
        base = base if base.endswith("/") else base + "/"
    return base


async def fetch_files(
    client: httpx.AsyncClient,
    url: str,
    rel_paths: list[str],
    *,
    path: str | None = None,
    concurrency: int = 8,
    max_bytes: int = 8 * 1024 * 1024,
    on_fetch: FetchEvent = None,
) -> FetchOutcome:
    """Download `rel_paths` relative to `url` (+ optional sub-`path`) and hash each one.

    `on_fetch(rel, kind, detail)` is invoked as each file resolves (for verbose reporting).
    """
    base = _base(url, path)
    sem = asyncio.Semaphore(concurrency)
    outcome = FetchOutcome()
    cache: dict[str, tuple[str, str]] = {}  # candidate url-path -> (kind, detail) to avoid refetch

    def emit(rel: str, kind: str, detail: str) -> None:
        if on_fetch is not None:
            on_fetch(rel, kind, detail)

    async def fetch_candidate(cand: str) -> tuple[str, str]:
        """Fetch one URL-relative path -> ("hash", oid) | ("miss", detail) | ("error", detail)."""
        if cand in cache:
            return cache[cand]
        target = urljoin(base, cand.lstrip("/"))
        async with sem:
            try:
                # Do NOT follow redirects for assets: a static file that 3xx-redirects is not
                # actually served here (often a redirect to a marketing site), so the redirect
                # body must never be hashed as if it were the asset.
                resp = await client.get(target, follow_redirects=False)
            except httpx.HTTPError as exc:
                result = ("error", str(exc))
                cache[cand] = result
                return result
        if resp.status_code != 200:
            result = ("miss", f"HTTP {resp.status_code}")
        else:
            # SPA/login fallbacks return 200 + HTML for unknown asset paths. We only fingerprint
            # JS/CSS/images/json/fonts, never HTML, so HTML means the asset isn't really there.
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype in ("text/html", "application/xhtml+xml"):
                result = ("miss", "html response")
            elif len(resp.content) > max_bytes:
                result = ("miss", "too large")
            else:
                # detail = space-joined OID variants: primary (raw) first, then fallbacks.
                result = ("hash", " ".join(git_blob_hash_variants(resp.content)))
        cache[cand] = result
        return result

    async def one(rel: str) -> None:
        # Try the indexed path, then web-root-prefix-stripped variants; first hit wins. The match
        # key stays the original `rel`, so only the fetch URL adapts to the deployment layout.
        last = ("miss", "not served")
        for cand in served_candidates(rel):
            kind, detail = await fetch_candidate(cand)
            if kind == "hash":
                oids = detail.split()
                outcome.hashes[rel] = oids[0]
                if len(oids) > 1:
                    outcome.alt_hashes[rel] = oids[1:]
                emit(rel, "fingerprint", oids[0])
                return
            last = (kind, detail)
        if last[0] == "error":
            outcome.errors[rel] = last[1]
            emit(rel, "error", last[1])
        else:
            outcome.missing.append(rel)
            emit(rel, "miss", last[1])

    await asyncio.gather(*(one(r) for r in rel_paths))
    return outcome


def make_client(timeout: float = 10.0, verify: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=True,
        headers={"User-Agent": DEFAULT_UA},
    )
