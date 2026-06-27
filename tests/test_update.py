"""Tests for the interactive-update flow (pure helpers + non-interactive --check/--download paths)."""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from CommiPiste import dbfetch, update
from CommiPiste.config import get_settings


def _make_db(path: Path, n: int = 5) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany("INSERT INTO projects (name) VALUES (?)", [(f"p{i}",) for i in range(n)])
    conn.commit()
    conn.close()


def _publish(reldir: Path, build_date: str, n: int = 5) -> Path:
    """Create a fake release dir with signatures.db.gz + signatures.json; return the .gz path."""
    reldir.mkdir(parents=True, exist_ok=True)
    raw = reldir / "signatures.db"
    _make_db(raw, n)
    gz = reldir / "signatures.db.gz"
    gz.write_bytes(gzip.compress(raw.read_bytes()))
    sha = hashlib.sha256(raw.read_bytes()).hexdigest()
    (reldir / "signatures.json").write_text(
        json.dumps({"schema": 1, "build_date": build_date, "projects": n, "db_sha256": sha})
    )
    raw.unlink()
    return gz


# --- pure helpers ---------------------------------------------------------- #

def test_is_newer():
    assert update.is_newer({"build_date": "2030-01-02T00:00:00Z"}, "2030-01-01T00:00:00Z")
    assert not update.is_newer({"build_date": "2030-01-01T00:00:00Z"}, "2030-01-02T00:00:00Z")
    assert update.is_newer({"build_date": "2030-01-01T00:00:00Z"}, None)  # no local -> newer
    assert not update.is_newer({}, "2030-01-01T00:00:00Z")                # unknown remote -> not


def test_is_today():
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert update.is_today(today)
    assert not update.is_today("2000-01-01T00:00:00Z")
    assert not update.is_today(None)


def test_local_meta_roundtrip(tmp_path):
    s = get_settings(home=tmp_path / "home")
    dbfetch.write_local_meta(s, {"acquired_at": "x", "build_date": "y", "projects": 3})
    assert dbfetch.read_local_meta(s)["build_date"] == "y"
    assert dbfetch.local_build_date(s) == "y"


# --- non-interactive flow paths -------------------------------------------- #

def test_check_reports_update_when_no_local_db(tmp_path, monkeypatch):
    gz = _publish(tmp_path / "rel", "2030-01-01T00:00:00Z")
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(gz))
    s = get_settings(home=tmp_path / "home")
    assert update.interactive_update(s, None, check=True) == 1  # no local -> update available


def test_download_when_newer_records_meta(tmp_path, monkeypatch):
    gz = _publish(tmp_path / "rel", "2030-06-19T10:00:00Z", n=7)
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(gz))
    s = get_settings(home=tmp_path / "home")

    rc = update.interactive_update(s, None, download=True)
    assert rc == 0
    assert s.db_path.exists()
    meta = dbfetch.read_local_meta(s)
    assert meta["build_date"] == "2030-06-19T10:00:00Z"
    assert meta["projects"] == 7
    assert dbfetch._safe_project_count(s.db_path) == 7


def test_check_up_to_date(tmp_path, monkeypatch):
    gz = _publish(tmp_path / "rel", "2020-01-01T00:00:00Z")
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(gz))
    s = get_settings(home=tmp_path / "home")
    # Local DB built far in the future -> remote is not newer.
    _make_db(s.db_path if (s.ensure_dirs() or True) else s.db_path)
    dbfetch.write_local_meta(s, {"acquired_at": "2099-01-01T00:00:00Z",
                                 "build_date": "2099-01-01T00:00:00Z", "projects": 5})
    assert update.interactive_update(s, None, check=True) == 0


def test_download_sha_mismatch_fails(tmp_path, monkeypatch):
    reldir = tmp_path / "rel"
    gz = _publish(reldir, "2030-01-01T00:00:00Z")
    # Corrupt the manifest's sha so verification fails.
    man = json.loads((reldir / "signatures.json").read_text())
    man["db_sha256"] = "deadbeef" * 8
    (reldir / "signatures.json").write_text(json.dumps(man))
    monkeypatch.setenv("COMMIPISTE_DB_URL", str(gz))
    s = get_settings(home=tmp_path / "home")
    assert update.interactive_update(s, None, download=True) == 1
    assert not s.db_path.exists()


def test_reindex_local_restores_missing(fake_repo, tmp_path) -> None:
    """After a download leaves the DB without a local (autoindexed) project, _do_download's restore
    step re-indexes it from the local registry so the download doesn't silently drop it."""
    from CommiPiste.models import Project
    from CommiPiste.registry.loader import Registry

    settings = get_settings(home=tmp_path / "home")
    settings.ensure_dirs()  # empty DB: simulates a freshly downloaded base without our local project
    reg = Registry({
        "mine": Project(name="mine", repo_url=str(fake_repo.path),
                        public_paths=["public"], is_local=True),
    })
    assert "mine" not in update._indexed_platforms(settings, reg)

    update._reindex_local_projects(settings, reg)

    assert "mine" in update._indexed_platforms(settings, reg)
