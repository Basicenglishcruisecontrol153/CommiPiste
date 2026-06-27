"""Download a prebuilt signature database so the tool works on first run.

Scanning needs a signature DB (`hash → paths → commits`), which is generated data and not shipped
in the repo. Building it locally is slow (clones several GB). To make the first run "just work",
``fetch_db`` pulls a ready-made ``signatures.db`` from an HTTP(S) URL **or** a local path into
``$COMMIPISTE_HOME/signatures.db``.

Source resolution: an explicit argument wins, otherwise the ``COMMIPISTE_DB_URL`` environment
variable. ``.gz`` sources are decompressed transparently. The download is atomic (written to a
temp file, validated as a real SQLite database, then moved into place), and an existing DB is never
overwritten unless ``force`` is set.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import httpx

from .config import Settings

ENV_DB_URL = "COMMIPISTE_DB_URL"
# Token env vars (first set wins) — needed only when the release is in a PRIVATE GitHub repo, whose
# asset downloads require auth. Public repos need nothing.
ENV_DB_TOKEN = ("COMMIPISTE_DB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")

# Where the prebuilt DB is published. The signature DB is a GitHub Release asset (not committed to
# the repo): the `latest/download` URL always points at the newest release, and `.gz` is fetched +
# decompressed transparently. Override per-run with the COMMIPISTE_DB_URL env var. Leave the repo
# slug empty to disable auto-download (the scan then just nudges the user).
_DEFAULT_REPO = "soxoj/CommiPiste"  # private repo -> downloads need a token (see ENV_DB_TOKEN)
DEFAULT_DB_URL = (
    f"https://github.com/{_DEFAULT_REPO}/releases/latest/download/signatures.db.gz"
    if _DEFAULT_REPO
    else ""
)

# The release also carries a `signatures.json` manifest (build date, project count, sha256) next to
# the .gz, so `interactive-update` can tell whether a newer DB exists without downloading it.
MANIFEST_NAME = "signatures.json"
LOCAL_META_NAME = "signatures.meta.json"

_SQLITE_MAGIC = b"SQLite format 3\x00"
# Progress callback: (downloaded_bytes, total_bytes_or_None).
ProgressCb = Optional[Callable[[int, Optional[int]], None]]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DBFetchError(RuntimeError):
    """Raised when the database cannot be fetched or is not a valid signature DB."""


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


_GH_TOKEN_CACHE: str | None | object = None  # sentinel: not yet probed
_UNSET = object()


def _token() -> str | None:
    """A GitHub token from the environment, else the logged-in `gh` CLI (cached).

    The env vars cover CI/headless; the `gh` fallback means a developer who's already `gh auth
    login`ed needs no extra config to pull a private-repo DB.
    """
    for k in ENV_DB_TOKEN:
        v = os.environ.get(k)
        if v:
            return v
    global _GH_TOKEN_CACHE
    if _GH_TOKEN_CACHE is None:
        _GH_TOKEN_CACHE = _UNSET
        if shutil.which("gh"):
            try:
                out = subprocess.run(
                    ["gh", "auth", "token"], capture_output=True, text=True, timeout=5
                )
                if out.returncode == 0 and out.stdout.strip():
                    _GH_TOKEN_CACHE = out.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass
    return None if _GH_TOKEN_CACHE is _UNSET else _GH_TOKEN_CACHE  # type: ignore[return-value]


_GH_RELEASE_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/releases/(?:latest/download|download/([^/]+))/(.+)$"
)


def _auth_hint(url: str) -> str:
    """Hint appended to a failed GitHub-release fetch when no auth was available (likely private)."""
    if _GH_RELEASE_RE.match(url) and not _token():
        return " — if the repo is private, set COMMIPISTE_DB_TOKEN / GH_TOKEN, or run `gh auth login`"
    return ""


def _resolve_download(url: str) -> tuple[str, dict]:
    """Resolve a download URL + headers.

    For a GitHub release-asset URL **with a token set**, look the asset up via the API and return its
    authenticated octet-stream URL — the only way private-repo assets download (the plain
    `releases/.../download/<name>` URL 404s without a browser session). Otherwise returns the URL
    unchanged with no headers (public assets / non-GitHub / no token).
    """
    token = _token()
    m = _GH_RELEASE_RE.match(url)
    if not (token and m):
        return url, {}
    owner, repo, tag, name = m.groups()
    api = f"https://api.github.com/repos/{owner}/{repo}/releases/" + (f"tags/{tag}" if tag else "latest")
    auth = {"Authorization": f"Bearer {token}"}
    rel = httpx.get(api, headers={**auth, "Accept": "application/vnd.github+json"},
                    follow_redirects=True, timeout=30.0)
    if rel.status_code != 200:
        raise DBFetchError(f"GitHub release lookup failed: HTTP {rel.status_code} for {api}")
    asset = next((a for a in rel.json().get("assets", []) if a.get("name") == name), None)
    if not asset:
        raise DBFetchError(f"asset {name!r} not found in {api}")
    # httpx drops the auth header on the cross-host redirect to the (pre-signed) storage URL — fine.
    return asset["url"], {**auth, "Accept": "application/octet-stream"}


def _download_http(url: str, dest: Path, progress: ProgressCb) -> None:
    eff, headers = _resolve_download(url)
    with httpx.stream("GET", eff, headers=headers, follow_redirects=True, timeout=30.0) as resp:
        if resp.status_code != 200:
            raise DBFetchError(f"download failed: HTTP {resp.status_code} from {url}{_auth_hint(url)}")
        total = int(resp.headers.get("content-length") or 0) or None
        done = 0
        with dest.open("wb") as fh:
            for chunk in resp.iter_bytes(chunk_size=1 << 16):
                fh.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)


def _copy_local(src: Path, dest: Path, progress: ProgressCb) -> None:
    if not src.is_file():
        raise DBFetchError(f"no such file: {src}")
    total = src.stat().st_size
    done = 0
    with src.open("rb") as r, dest.open("wb") as w:
        while chunk := r.read(1 << 16):
            w.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)


def _gunzip(src: Path, dest: Path) -> None:
    with gzip.open(src, "rb") as r, dest.open("wb") as w:
        shutil.copyfileobj(r, w)


def _safe_project_count(path: Path) -> int:
    """Project count if `path` is a usable signature DB, else 0 (missing/empty/invalid/stub)."""
    if not path.exists():
        return 0
    try:
        return _validate_sqlite(path)
    except (DBFetchError, OSError):
        return 0


def _validate_sqlite(path: Path) -> int:
    """Confirm `path` is a SQLite signature DB; return the number of indexed projects."""
    with path.open("rb") as fh:
        if fh.read(16) != _SQLITE_MAGIC:
            raise DBFetchError("downloaded file is not a SQLite database (wrong magic header)")
    try:
        conn = sqlite3.connect(path)
        try:
            (count,) = conn.execute("SELECT count(*) FROM projects").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise DBFetchError(f"downloaded file is not a valid signature DB: {exc}") from exc
    return int(count)


# --------------------------------------------------------------------------- #
# release manifest + local acquisition metadata                                #
# --------------------------------------------------------------------------- #


def resolve_manifest_source(explicit: str | None = None) -> str:
    """URL of the release manifest (`signatures.json`), derived from the DB source's directory."""
    if explicit:
        return explicit
    src = resolve_source()
    if not src:
        return ""
    if _is_url(src):
        return src.rsplit("/", 1)[0] + "/" + MANIFEST_NAME
    return str(Path(src).expanduser().parent / MANIFEST_NAME)


def fetch_manifest(source: str | None = None, *, timeout: float = 15.0) -> dict:
    """Fetch and parse the published release manifest. Raises :class:`DBFetchError` on failure."""
    url = resolve_manifest_source(source)
    if not url:
        raise DBFetchError("no manifest source configured (set COMMIPISTE_DB_URL)")
    try:
        if _is_url(url):
            eff, headers = _resolve_download(url)
            resp = httpx.get(eff, headers=headers, follow_redirects=True, timeout=timeout)
            if resp.status_code != 200:
                raise DBFetchError(
                    f"manifest fetch failed: HTTP {resp.status_code} from {url}{_auth_hint(url)}"
                )
            return resp.json()
        return json.loads(Path(url).read_text())
    except (httpx.HTTPError, ValueError, OSError) as exc:
        raise DBFetchError(f"could not read manifest: {exc}") from exc


def meta_path(settings: Settings) -> Path:
    return settings.home / LOCAL_META_NAME


def read_local_meta(settings: Settings) -> dict | None:
    """Local acquisition metadata written when the DB was last fetched/built, or None."""
    p = meta_path(settings)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (ValueError, OSError):
        return None


def write_local_meta(settings: Settings, meta: dict) -> None:
    settings.ensure_dirs()
    meta_path(settings).write_text(json.dumps(meta, indent=2))


def local_build_date(settings: Settings) -> str | None:
    """When the local DB's *data* was built (from meta), if known."""
    m = read_local_meta(settings)
    return (m or {}).get("build_date")


def local_acquired_date(settings: Settings) -> str | None:
    """ISO date the local DB was acquired (meta `acquired_at`, else the DB file's mtime)."""
    m = read_local_meta(settings)
    if m and m.get("acquired_at"):
        return m["acquired_at"]
    db = settings.db_path
    if db.exists():
        return datetime.fromtimestamp(db.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def fetch_db(
    settings: Settings,
    source: str | None = None,
    *,
    force: bool = False,
    progress: ProgressCb = None,
    build_date: str | None = None,
    expected_sha256: str | None = None,
) -> tuple[Path, int]:
    """Fetch the signature DB into ``settings.db_path``. Returns (path, project_count).

    `source` may be an HTTP(S) URL or a local file path (``.gz`` allowed); if omitted, falls back to
    the ``COMMIPISTE_DB_URL`` environment variable. On success it records local acquisition
    metadata (``signatures.meta.json``). If `expected_sha256` is given, the decompressed DB is
    verified against it. Raises :class:`DBFetchError` on any problem.
    """
    dest = settings.db_path
    # Only protect a DB that actually holds signatures. An empty stub (auto-created by a prior
    # `scan` before any DB existed) is safe to replace, so first-run isn't a chicken-and-egg trap.
    if dest.exists() and not force and _safe_project_count(dest) > 0:
        raise DBFetchError(
            f"a database with signatures already exists at {dest} — pass force=True (CLI: --force) "
            "to overwrite it"
        )

    src = source or os.environ.get(ENV_DB_URL)
    if not src:
        raise DBFetchError(
            "no source given: pass a URL or local path, or set the "
            f"{ENV_DB_URL} environment variable"
        )

    settings.ensure_dirs()
    is_gz = src.endswith(".gz")
    raw = dest.with_name(dest.name + (".part.gz" if is_gz else ".part"))
    try:
        if _is_url(src):
            _download_http(src, raw, progress)
        else:
            _copy_local(Path(src).expanduser(), raw, progress)

        final_tmp = dest.with_name(dest.name + ".part") if is_gz else raw
        if is_gz:
            _gunzip(raw, final_tmp)

        if expected_sha256:
            got = hashlib.sha256(final_tmp.read_bytes()).hexdigest()
            if got.lower() != expected_sha256.lower():
                raise DBFetchError(f"sha256 mismatch: expected {expected_sha256}, got {got}")
        count = _validate_sqlite(final_tmp)
        final_tmp.replace(dest)  # atomic move into place
        write_local_meta(settings, {
            "acquired_at": _now_iso(),
            "build_date": build_date,  # from the release manifest, if the caller had one
            "source": src,
            "projects": count,
        })
        return dest, count
    finally:
        # Clean up any leftover temp files on success or failure.
        for leftover in (raw, dest.with_name(dest.name + ".part")):
            if leftover != dest and leftover.exists():
                leftover.unlink()


def resolve_source(explicit: str | None = None) -> str:
    """Where to fetch the DB from: explicit arg → COMMIPISTE_DB_URL → built-in default."""
    return explicit or os.environ.get(ENV_DB_URL) or DEFAULT_DB_URL


def ensure_db(
    settings: Settings,
    *,
    log: Callable[[str], None] | None = None,
    progress: ProgressCb = None,
) -> bool:
    """Make sure a usable signature DB is present, auto-downloading it on first run.

    No-op (returns True) when a DB with signatures already exists. Otherwise resolves a source
    (env/default) and downloads it; returns False if nothing is configured to fetch from or the
    download fails (the caller can then degrade gracefully — scanning still works for active-probe
    apps and reports "not indexed" for the rest).
    """
    if _safe_project_count(settings.db_path) > 0:
        return True
    src = resolve_source()
    if not src:
        return False
    if log:
        log(f"no signature DB found — downloading it from {src} …")
    try:
        # force=True is safe here: we only reach this when there is no real data (missing or stub).
        _, count = fetch_db(settings, src, force=True, progress=progress)
    except DBFetchError as exc:
        if log:
            log(f"auto-download failed: {exc}")
        return False
    if log:
        log(f"signature DB ready ({count} projects)")
    return True
