"""Tests for the prebuilt-DB fetcher (`CommiPiste fetch-db`)."""

from __future__ import annotations

import gzip
import sqlite3
from pathlib import Path

import pytest

from CommiPiste import dbfetch
from CommiPiste.config import get_settings
from CommiPiste.dbfetch import DBFetchError, ensure_db, fetch_db, resolve_source


def _make_db(path: Path, projects: int = 3) -> None:
    """Write a minimal but valid signature DB (just enough for _validate_sqlite)."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany("INSERT INTO projects (name) VALUES (?)", [(f"p{i}",) for i in range(projects)])
    conn.commit()
    conn.close()


def test_fetch_from_local_path(tmp_path: Path) -> None:
    src = tmp_path / "src.db"
    _make_db(src, projects=5)
    settings = get_settings(home=tmp_path / "home")

    dest, count = fetch_db(settings, str(src))
    assert dest == settings.db_path
    assert dest.exists()
    assert count == 5
    # No temp files left behind.
    assert not list(settings.home.glob("*.part*"))


def test_fetch_from_gzip(tmp_path: Path) -> None:
    raw = tmp_path / "src.db"
    _make_db(raw, projects=2)
    gz = tmp_path / "src.db.gz"
    gz.write_bytes(gzip.compress(raw.read_bytes()))
    settings = get_settings(home=tmp_path / "home")

    dest, count = fetch_db(settings, str(gz))
    assert count == 2
    # The destination is the decompressed SQLite file, not the gzip.
    assert dest.read_bytes()[:16] == b"SQLite format 3\x00"


def test_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    src = tmp_path / "src.db"
    _make_db(src)
    settings = get_settings(home=tmp_path / "home")
    fetch_db(settings, str(src))  # first fetch creates it

    with pytest.raises(DBFetchError, match="already exists"):
        fetch_db(settings, str(src))
    # --force overwrites.
    _, count = fetch_db(settings, str(src), force=True)
    assert count == 3


def test_overwrites_empty_stub_without_force(tmp_path: Path) -> None:
    """An empty DB (e.g. auto-created by a prior `scan`) must not block the first real fetch."""
    settings = get_settings(home=tmp_path / "home")
    settings.ensure_dirs()
    _make_db(settings.db_path, projects=0)  # stub with zero signatures, like an auto-created DB

    src = tmp_path / "src.db"
    _make_db(src, projects=6)
    _, count = fetch_db(settings, str(src))  # no force needed
    assert count == 6


def test_rejects_non_sqlite_file(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.db"
    bogus.write_text("this is not a database")
    settings = get_settings(home=tmp_path / "home")

    with pytest.raises(DBFetchError, match="not a SQLite database"):
        fetch_db(settings, str(bogus))
    # A failed fetch leaves no DB and no temp files.
    assert not settings.db_path.exists()
    assert not list(settings.home.glob("*.part*"))


def _no_gh(monkeypatch):
    """Disable the env tokens and the `gh` CLI fallback so _token() reflects only what we set."""
    for k in ("COMMIPISTE_DB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(dbfetch, "_GH_TOKEN_CACHE", None)
    monkeypatch.setattr(dbfetch.shutil, "which", lambda *_: None)


def test_token_precedence(monkeypatch):
    _no_gh(monkeypatch)
    assert dbfetch._token() is None
    monkeypatch.setenv("GITHUB_TOKEN", "g")
    assert dbfetch._token() == "g"
    monkeypatch.setenv("COMMIPISTE_DB_TOKEN", "primary")
    assert dbfetch._token() == "primary"  # COMMIPISTE_DB_TOKEN wins


def test_resolve_download_passthrough(monkeypatch):
    _no_gh(monkeypatch)
    url = "https://github.com/o/r/releases/latest/download/signatures.db.gz"
    assert dbfetch._resolve_download(url) == (url, {})           # no token -> unchanged
    monkeypatch.setenv("COMMIPISTE_DB_TOKEN", "t")
    other = "https://example.com/x.db.gz"
    assert dbfetch._resolve_download(other) == (other, {})       # non-GitHub -> unchanged


def test_no_source_errors_clearly(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("COMMIPISTE_DB_URL", raising=False)
    settings = get_settings(home=tmp_path / "home")
    with pytest.raises(DBFetchError, match="no source"):
        fetch_db(settings, None)


def test_env_var_fallback(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "src.db"
    _make_db(src, projects=7)
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(src))
    settings = get_settings(home=tmp_path / "home")

    _, count = fetch_db(settings, None)  # source resolved from the env var
    assert count == 7


def test_fetch_over_http(tmp_path: Path, httpserver) -> None:
    src = tmp_path / "src.db"
    _make_db(src, projects=4)
    httpserver.expect_request("/signatures.db").respond_with_data(
        src.read_bytes(), content_type="application/octet-stream"
    )
    settings = get_settings(home=tmp_path / "home")

    dest, count = fetch_db(settings, httpserver.url_for("/signatures.db"))
    assert count == 4
    assert dest.read_bytes()[:16] == b"SQLite format 3\x00"


def test_http_404_is_clean(tmp_path: Path, httpserver) -> None:
    httpserver.expect_request("/missing.db").respond_with_data("nope", status=404)
    settings = get_settings(home=tmp_path / "home")

    with pytest.raises(DBFetchError, match="HTTP 404"):
        fetch_db(settings, httpserver.url_for("/missing.db"))
    assert not settings.db_path.exists()


def test_resolve_source_precedence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("COMMIPISTE_DB_URL", "http://env/db")
    assert resolve_source("http://explicit/db") == "http://explicit/db"  # explicit wins
    assert resolve_source() == "http://env/db"                            # then env
    monkeypatch.delenv("COMMIPISTE_DB_URL", raising=False)
    # falls back to the built-in default (empty until a repo slug is baked in)
    from CommiPiste.dbfetch import DEFAULT_DB_URL
    assert resolve_source() == DEFAULT_DB_URL


def test_ensure_db_noop_when_present(tmp_path: Path) -> None:
    settings = get_settings(home=tmp_path / "home")
    settings.ensure_dirs()
    _make_db(settings.db_path, projects=3)  # already populated
    # No source configured, but ensure_db must still succeed without touching the network.
    assert ensure_db(settings) is True


def test_ensure_db_downloads_on_first_run(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "src.db"
    _make_db(src, projects=9)
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(src))
    settings = get_settings(home=tmp_path / "home")

    assert ensure_db(settings) is True
    assert settings.db_path.exists()


def test_ensure_db_false_when_unconfigured(tmp_path: Path, monkeypatch) -> None:
    for k in ("COMMIPISTE_DB_URL", "COMMIPISTE_DB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(dbfetch, "DEFAULT_DB_URL", "")  # neutralize the baked-in default repo
    settings = get_settings(home=tmp_path / "home")
    # No DB and no source -> graceful False (caller degrades, does not crash).
    assert ensure_db(settings) is False
