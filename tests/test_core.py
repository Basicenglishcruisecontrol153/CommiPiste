"""Core unit tests: hashing parity, indexing, and the matching algorithm."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.matcher import match_project
from CommiPiste.hashing import git_blob_hash
from CommiPiste.indexer.builder import index_project
from CommiPiste.models import Project
from CommiPiste.storage import open_storage


def test_git_blob_hash_matches_git(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_bytes(b"hello CommiPiste\n")
    expected = subprocess.run(
        ["git", "hash-object", str(f)], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert git_blob_hash(f.read_bytes()) == expected


def _project(repo) -> Project:
    return Project(name="fake", repo_url=str(repo.path), public_paths=["public"])


async def _index(repo, tmp_path) -> tuple:
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    stats = await index_project(_project(repo), settings=settings, storage=store)
    return settings, store, stats


@pytest.mark.asyncio
async def test_indexing_records_signatures(fake_repo, tmp_path) -> None:
    _, store, stats = await _index(fake_repo, tmp_path)
    try:
        assert stats.refs_indexed == 3  # three tags
        assert stats.stats["refs"] == 3
        # app.js: APP-v1/APP-v11/APP-v2 (3) + lib.js: LIB-a/LIB-b (2) = 5 unique blobs
        assert stats.stats["blobs"] == 5
        paths = await store.indexed_paths(1)
        assert paths == {"public/app.js", "public/lib.js"}
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_exact_match_single_commit(fake_repo, tmp_path) -> None:
    _, store, _ = await _index(fake_repo, tmp_path)
    try:
        meta = await store.get_project("fake")
        observed = {
            "public/app.js": git_blob_hash(b"APP-v11"),
            "public/lib.js": git_blob_hash(b"LIB-a"),
        }
        finding = await match_project(store, meta, "fake", observed, detected_by="user")
        assert finding.confidence.exact
        assert finding.commit_sha == fake_repo.tag_to_sha["v1.1"]
        assert finding.version == "v1.1"
        assert finding.commit_url.endswith("/tree/" + fake_repo.tag_to_sha["v1.1"])
        assert not finding.modified
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_ambiguous_yields_candidate_range(fake_repo, tmp_path) -> None:
    _, store, _ = await _index(fake_repo, tmp_path)
    try:
        meta = await store.get_project("fake")
        # lib.js=LIB-a is shared by v1.0 and v1.1 -> two candidates when app.js is not probed.
        observed = {"public/lib.js": git_blob_hash(b"LIB-a")}
        finding = await match_project(store, meta, "fake", observed, detected_by="user")
        assert not finding.confidence.exact
        assert finding.confidence.candidate_count == 2
        assert set(finding.commit_range) == {
            fake_repo.tag_to_sha["v1.0"],
            fake_repo.tag_to_sha["v1.1"],
        }
        # The candidates are surfaced by version name, with the file that pins exactly them.
        # (Fixture commits share a date, so order falls to sha; compare as a set.)
        assert set(finding.candidate_versions) == {"v1.0", "v1.1"}
        assert finding.key_files == ["public/lib.js"]
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_incremental_update_indexes_only_new_refs(fake_repo, tmp_path) -> None:
    settings, store, first = await _index(fake_repo, tmp_path)
    try:
        assert first.refs_indexed == 3

        # Add a new release to the source repo.
        env = {
            "PATH": __import__("os").environ["PATH"],
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e",
            "GIT_AUTHOR_DATE": "2021-01-01T00:00:00",
            "GIT_COMMITTER_DATE": "2021-01-01T00:00:00",
        }
        (fake_repo.path / "public" / "app.js").write_text("APP-v3")
        subprocess.run(["git", "-C", str(fake_repo.path), "commit", "-aqm", "v3.0"],
                       check=True, env=env)
        subprocess.run(["git", "-C", str(fake_repo.path), "tag", "v3.0"], check=True, env=env)

        second = await index_project(
            _project(fake_repo), settings=settings, storage=store, update=True
        )
        assert second.refs_indexed == 1  # only v3.0
        assert second.stats["refs"] == 4
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_modified_deployment_flagged(fake_repo, tmp_path) -> None:
    _, store, _ = await _index(fake_repo, tmp_path)
    try:
        meta = await store.get_project("fake")
        observed = {
            "public/app.js": git_blob_hash(b"APP-v11"),
            "public/lib.js": git_blob_hash(b"PATCHED-BY-OPERATOR"),  # matches no ref
        }
        finding = await match_project(store, meta, "fake", observed, detected_by="user")
        assert finding.modified
        assert any(d.kind == "unknown_hash" for d in finding.discrepancies)
        # The app.js match still pins it to v1.1.
        assert finding.commit_sha == fake_repo.tag_to_sha["v1.1"]
    finally:
        await store.close()
