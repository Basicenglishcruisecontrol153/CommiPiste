"""Characterization (golden) tests for the matcher on WIDE candidate clusters.

These pin the matcher's CURRENT behaviour on the two cluster shapes that rarity-weighting (roadmap
item #2, IDF) would touch, so that when #2 lands the diff is explicit and any unintended change is
caught:

  * ``wide_cluster_repo`` — a genuine collision class (many releases share identical assets). #2 is
    rank-only here and MUST NOT prune the set; this test is the CONTROL and should stay green
    unchanged after #2.

  * ``tie_cluster_repo`` — an inconsistent deployment that falls back to flat plurality
    (``_max_support``), where every release ties on raw file-count. This test pins the BEFORE
    (flat) answer; #2 (weighted support) is expected to narrow it, so the marked asserts are the
    ones that will deliberately flip — update them when #2 lands.

Both are hermetic (synthetic git repos, no network), so the lock is deterministic.
"""

from __future__ import annotations

import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.matcher import match_project
from CommiPiste.hashing import git_blob_hash
from CommiPiste.indexer.builder import index_project
from CommiPiste.models import Project
from CommiPiste.storage import open_storage

_V36 = {"v3.6.10", "v3.6.11", "v3.6.12", "v3.6.13", "v3.6.14", "v3.6.15", "v3.6.16"}


async def _match(repo, tmp_path, observed_text: dict[str, str]):
    """Index a fixture repo and match a deployment given as {rel_path: served content}."""
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(
        Project(name="fake", repo_url=str(repo.path), public_paths=["public"]),
        settings=settings, storage=store,
    )
    meta = await store.get_project("fake")
    observed = {p: git_blob_hash(v.encode()) for p, v in observed_text.items()}
    try:
        return await match_project(store, meta, "fake", observed, detected_by="user")
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_wide_collision_class_is_not_pruned(wide_cluster_repo, tmp_path) -> None:
    """CONTROL: serving only the band-common files yields the whole v3.6.x collision class.

    There is no rare signal to split these seven releases, so rarity-weighting must leave the set
    intact. This block is expected to remain UNCHANGED after #2 (rank-only) — if #2 ever makes it
    fail, #2 is wrongly pruning a genuine collision class.
    """
    f = await _match(
        wide_cluster_repo, tmp_path,
        {"public/jquery.js": "JQ-old", "public/base.css": "BASE-old"},
    )
    assert f.match_basis == "exact"           # non-empty intersection...
    assert not f.confidence.exact             # ...but more than one commit -> not pinned
    assert f.confidence.candidate_count == 7
    assert set(f.candidate_versions) == _V36
    assert "v3.7.0" not in f.candidate_versions   # the out-of-band release is correctly excluded
    assert f.version is not None and f.version.startswith("v3.6.")  # best stays within the band
    assert not f.modified
    assert f.confidence.score == 1.0          # 2/2 served files matched
    assert f.confidence.label == "medium"


@pytest.mark.asyncio
async def test_support_tie_flat_plurality_before_idf(tie_cluster_repo, tmp_path) -> None:
    """BEFORE #2: an inconsistent deployment ties under flat plurality across all three releases.

    common.js matches all three, pair.css matches {v1,v2}, uniq.js matches {v3}; the intersection
    is empty, so resolution falls to ``_max_support`` and every release ends up tied. The matcher
    reports the full set and picks the latest as ``best``.
    """
    f = await _match(
        tie_cluster_repo, tmp_path,
        {"public/common.js": "C", "public/pair.css": "P12", "public/uniq.js": "U3"},
    )
    assert f.match_basis == "support"
    assert f.modified                          # empty intersection => inconsistent/patched
    # The rare file already sorts first in the evidence (smallest ref-set pins hardest).
    assert f.key_files and f.key_files[0] == "public/uniq.js"

    # --- BEFORE #2 (flat plurality): all three releases tie and are all reported. -------------
    # AFTER #2 (rarity-weighted support) EXPECT this to narrow to just {"v3.0"} (uniq.js, freq 1,
    # outweighs common.js freq 3 + pair.css freq 2). Update these three asserts when #2 lands:
    # candidate_count 3 -> 1, the set -> {"v3.0"}, the range length 3 -> 1.
    assert f.confidence.candidate_count == 3
    assert set(f.candidate_versions) == {"v1.0", "v2.0", "v3.0"}
    assert len(f.commit_range) == 3
    # `version` (best) is sha-arbitrary while the three tie on equal dates, so only pin membership;
    # after #2 the tie is broken and best becomes "v3.0".
    assert f.version in {"v1.0", "v2.0", "v3.0"}
