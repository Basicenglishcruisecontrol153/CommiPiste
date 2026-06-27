"""Shared test fixtures: build throwaway git repos with a public dir across tags."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
    # Deterministic dates.
    "GIT_AUTHOR_DATE": "2020-01-01T00:00:00",
    "GIT_COMMITTER_DATE": "2020-01-01T00:00:00",
}


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": __import__("os").environ["PATH"], **_ENV},
    )
    return out.stdout.strip()


@dataclass
class FakeRepo:
    path: Path
    tag_to_sha: dict[str, str] = field(default_factory=dict)
    # public/app.js content per tag, to assert hashes later.
    tag_to_files: dict[str, dict[str, str]] = field(default_factory=dict)


def _commit_tag(repo: FakeRepo, tag: str, files: dict[str, str]) -> None:
    public = repo.path / "public"
    public.mkdir(exist_ok=True)
    for rel, content in files.items():
        fp = repo.path / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
    _git(repo.path, "add", "-A")
    _git(repo.path, "commit", "-q", "-m", tag)
    _git(repo.path, "tag", tag)
    repo.tag_to_sha[tag] = _git(repo.path, "rev-parse", "HEAD")
    repo.tag_to_files[tag] = dict(files)


@pytest.fixture
def fake_repo(tmp_path: Path) -> FakeRepo:
    """Three released versions; public/app.js changes each release, public/lib.js changes once."""
    repo = FakeRepo(path=tmp_path / "src")
    repo.path.mkdir()
    _git(repo.path, "init", "-q")
    _git(repo.path, "branch", "-m", "main")
    (repo.path / "README").write_text("not public")  # outside public/, never served

    _commit_tag(repo, "v1.0", {"public/app.js": "APP-v1", "public/lib.js": "LIB-a"})
    _commit_tag(repo, "v1.1", {"public/app.js": "APP-v11", "public/lib.js": "LIB-a"})
    _commit_tag(repo, "v2.0", {"public/app.js": "APP-v2", "public/lib.js": "LIB-b"})
    return repo


@pytest.fixture
def core_with_plugin(tmp_path: Path):
    """A 'core' app and a 'plugin' (served under the core's web root, like a WordPress plugin)."""
    core = FakeRepo(path=tmp_path / "core")
    core.path.mkdir()
    _git(core.path, "init", "-q")
    _git(core.path, "branch", "-m", "main")
    _commit_tag(core, "v1.0", {"assets/core.js": "CORE-1"})
    _commit_tag(core, "v2.0", {"assets/core.js": "CORE-2"})

    plugin = FakeRepo(path=tmp_path / "plugin")
    plugin.path.mkdir()
    _git(plugin.path, "init", "-q")
    _git(plugin.path, "branch", "-m", "main")
    _commit_tag(plugin, "v1.0", {"assets/app.js": "PL-1"})
    _commit_tag(plugin, "v2.0", {"assets/app.js": "PL-2"})
    return core, plugin


@pytest.fixture
def webroot_repo(tmp_path: Path) -> FakeRepo:
    """App whose assets live under public/ in the repo (Moodle 5.x / Redmine / Rails layout).

    Deployed servers serve public/ as the web root, so the same files appear at /app.js, not
    /public/app.js. Indexed without repo_subdir, scan-time path normalization must still match.
    """
    repo = FakeRepo(path=tmp_path / "src")
    repo.path.mkdir()
    _git(repo.path, "init", "-q")
    _git(repo.path, "branch", "-m", "main")
    _commit_tag(repo, "v1.0", {"public/app.js": "APP-1", "public/style.css": "CSS-1"})
    _commit_tag(repo, "v2.0", {"public/app.js": "APP-2", "public/style.css": "CSS-2"})
    return repo


@pytest.fixture
def wide_cluster_repo(tmp_path: Path) -> FakeRepo:
    """Phplist-style WIDE collision class: many releases that share identical static assets.

    Eight releases where jquery.js + base.css are byte-identical across the SEVEN v3.6.x releases
    and only change at v3.7.0. (They must change at least once, or the indexer prunes them as
    invariant/non-discriminating.) A deployment serving the v3.6.x copies of those two files
    intersects to the whole v3.6.x band — an honest collision class the served bytes cannot split.
    This is the case rarity-weighting (#2) must NOT prune: there is no rare signal, so the candidate
    set has to stay wide; only ranking/`best` may move.
    """
    repo = FakeRepo(path=tmp_path / "src")
    repo.path.mkdir()
    _git(repo.path, "init", "-q")
    _git(repo.path, "branch", "-m", "main")
    tags = ["v3.6.10", "v3.6.11", "v3.6.12", "v3.6.13", "v3.6.14", "v3.6.15", "v3.6.16", "v3.7.0"]
    for t in tags:
        new = t == "v3.7.0"
        _commit_tag(repo, t, {
            "VERSION": t,                                  # outside public/ -> keeps each commit distinct
            "public/jquery.js": "JQ-new" if new else "JQ-old",    # identical across the 7 v3.6.x (freq 7)
            "public/base.css": "BASE-new" if new else "BASE-old",  # identical across the 7 v3.6.x (freq 7)
        })
    return repo


@pytest.fixture
def tie_cluster_repo(tmp_path: Path) -> FakeRepo:
    """Support-fallback TIE: flat plurality cannot separate the releases, rarity can.

    Three releases. `common.js` is identical across all three (freq 3, weak); `pair.css` is shared
    by v1+v2 (freq 2); `uniq.js` is unique per release (freq 1, strong). A patched/mixed deployment
    serving common.js + pair.css(v1+v2 blob) + uniq.js(v3 blob) has an EMPTY intersection, so the
    matcher falls back to plurality `_max_support` — where the releases tie on raw file-count.
    Rarity-weighting (#2) would instead let the unique v3 file dominate. This golden pins the
    CURRENT (flat) answer so the change is visible after #2.
    """
    repo = FakeRepo(path=tmp_path / "src")
    repo.path.mkdir()
    _git(repo.path, "init", "-q")
    _git(repo.path, "branch", "-m", "main")
    _commit_tag(repo, "v1.0", {"public/common.js": "C", "public/pair.css": "P12", "public/uniq.js": "U1"})
    _commit_tag(repo, "v2.0", {"public/common.js": "C", "public/pair.css": "P12", "public/uniq.js": "U2"})
    _commit_tag(repo, "v3.0", {"public/common.js": "C", "public/pair.css": "P3",  "public/uniq.js": "U3"})
    return repo


@pytest.fixture
def mixed_repo(tmp_path: Path) -> FakeRepo:
    """Reproduces the owndrive case: an anchor file (server.css) that uniquely pins each release,
    plus many l10n files that change once at v2.0 and stay identical through v4.0.

    A deployment that serves v1.0's server.css but v2.0+ l10n (mixed/patched) makes the full
    intersection empty; flat plurality (6 l10n files vs 1 anchor) would wrongly pick v2.0–v4.0,
    while anchor resolution correctly reports v1.0.
    """
    repo = FakeRepo(path=tmp_path / "src")
    repo.path.mkdir()
    _git(repo.path, "init", "-q")
    _git(repo.path, "branch", "-m", "main")

    l10n_old = {f"public/l10n/f{i}.js": f"f{i}-old" for i in range(6)}
    l10n_new = {f"public/l10n/f{i}.js": f"f{i}-new" for i in range(6)}
    _commit_tag(repo, "v1.0", {"public/server.css": "CSS-1", **l10n_old})
    _commit_tag(repo, "v2.0", {"public/server.css": "CSS-2", **l10n_new})
    _commit_tag(repo, "v3.0", {"public/server.css": "CSS-3", **l10n_new})
    _commit_tag(repo, "v4.0", {"public/server.css": "CSS-4", **l10n_new})
    return repo
