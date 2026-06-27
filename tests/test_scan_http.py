"""End-to-end scan over real HTTP: serve a checkout of one tag, scan it, expect that commit."""

from __future__ import annotations

import functools
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.scan import scan_target
from CommiPiste.hashing import git_blob_hash
from CommiPiste.indexer.builder import index_project
from CommiPiste.models import BannerSpec, Project
from CommiPiste.registry.loader import Registry
from CommiPiste.storage import open_storage


def _serve(directory: Path):
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.mark.asyncio
async def test_scan_identifies_exact_commit(fake_repo, tmp_path) -> None:
    project = Project(
        name="fake",
        repo_url=str(fake_repo.path),
        public_paths=["public"],
        probe_files=["public/app.js", "public/lib.js"],
        banners=BannerSpec(body_regex=["APP-"]),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(project, settings=settings, storage=store)

    # Serve a checkout of v1.1's tree as the live "deployment".
    serve_dir = tmp_path / "deploy"
    serve_dir.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(fake_repo.path), "archive", "v1.1"],
        capture_output=True,
        check=True,
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(serve_dir)], input=archive, check=True)

    httpd, url = _serve(serve_dir)
    try:
        result = await scan_target(
            url,
            software="fake",
            settings=settings,
            storage=store,
            registry=Registry({"fake": project}),
            with_dependents=False,
        )
    finally:
        httpd.shutdown()
        await store.close()

    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.software == "fake"
    assert f.detected_by == "user"
    assert f.confidence.exact
    assert f.commit_sha == fake_repo.tag_to_sha["v1.1"]
    assert f.version == "v1.1"
    assert f.confidence.files_matched == 2


@pytest.mark.asyncio
async def test_scan_normalizes_webroot_prefix(webroot_repo, tmp_path) -> None:
    """Repo stores assets under public/, but the server serves them at the web root.

    Indexed WITHOUT repo_subdir (stored as public/app.js); the fetcher must try the prefix-stripped
    URL (/app.js) and still match against the stored path — no re-indexing needed.
    """
    project = Project(
        name="webapp",
        repo_url=str(webroot_repo.path),
        public_paths=["public"],  # NB: no repo_subdir — stored paths keep the public/ prefix
        probe_files=["public/app.js", "public/style.css"],
        banners=BannerSpec(paths=[{"path": "app.js", "match": "APP-"}]),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(project, settings=settings, storage=store)

    # Deployment serves assets at the WEB ROOT (no public/ segment), as Rails/Moodle-5 do.
    serve_dir = tmp_path / "deploy"
    serve_dir.mkdir()
    (serve_dir / "app.js").write_text("APP-2")
    (serve_dir / "style.css").write_text("CSS-2")

    httpd, url = _serve(serve_dir)
    try:
        result = await scan_target(
            url, software="webapp", settings=settings, storage=store,
            registry=Registry({"webapp": project}), with_dependents=False, concurrency=2,
        )
    finally:
        httpd.shutdown()
        await store.close()

    f = result.findings[0]
    assert f.commit_sha == webroot_repo.tag_to_sha["v2.0"], f.version
    assert f.version == "v2.0"
    assert f.confidence.exact
    assert f.confidence.files_matched == 2  # both matched via the stripped /app.js, /style.css


@pytest.mark.asyncio
async def test_scan_mixed_deployment_resolves_by_anchor(mixed_repo, tmp_path) -> None:
    """e2e for the owndrive situation: served core is v1.0 but l10n is v2.0+.

    The full intersection is empty and l10n files outnumber the anchor 6:1, so a flat-plurality
    matcher would pick v2.0–v4.0. The anchor (server.css) must pin v1.0, flag the deployment
    modified, and report the evidence version range.
    """
    project = Project(
        name="mixed",
        repo_url=str(mixed_repo.path),
        public_paths=["public"],
        # Anchors = curated CORE files only (like nextcloud.yaml). The l10n files are still
        # fetched/matched via discriminators, but they are NOT trusted anchors.
        probe_files=["public/server.css"],
        banners=BannerSpec(paths=[{"path": "public/server.css", "match": "CSS-"}]),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(project, settings=settings, storage=store)

    # Build a MIXED deployment by hand: v1.0 core CSS, but v2.0+ l10n content.
    serve_dir = tmp_path / "deploy"
    (serve_dir / "public" / "l10n").mkdir(parents=True)
    (serve_dir / "public" / "server.css").write_text("CSS-1")  # v1.0 core
    for i in range(6):
        (serve_dir / "public" / "l10n" / f"f{i}.js").write_text(f"f{i}-new")  # v2.0+ l10n

    # Sanity: confirm the hashes we serve really map where we claim, before trusting the verdict.
    assert git_blob_hash(b"CSS-1") == subprocess.run(
        ["git", "-C", str(mixed_repo.path), "rev-parse", "v1.0:public/server.css"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    httpd, url = _serve(serve_dir)
    try:
        result = await scan_target(
            url, software="mixed", settings=settings, storage=store,
            registry=Registry({"mixed": project}), with_dependents=False,
            concurrency=2,  # gentle on the tiny local test server
        )
    finally:
        httpd.shutdown()
        await store.close()

    f = result.findings[0]
    # The anchor (server.css) pins v1.0 despite the l10n files pointing at v2.0–v4.0.
    assert f.commit_sha == mixed_repo.tag_to_sha["v1.0"], f.version
    assert f.version == "v1.0"
    assert f.match_basis == "anchor"
    assert f.modified is True
    # The mixed evidence is surfaced as a version range (proves both v1.0 anchor and newer l10n
    # were matched — i.e. it really was a conflict, not a clean single-version match).
    assert f.version_range == "v1.0 … v4.0"
    # server.css + at least one l10n (exact count varies with local-server fetch timing).
    assert f.confidence.files_matched >= 2


@pytest.mark.asyncio
async def test_scan_finds_dependent_plugin(core_with_plugin, tmp_path) -> None:
    """When the core app is found, a plugin served under its web root is also fingerprinted.

    The plugin is fetched at its served_prefix (wp-content/plugins/<slug>), presence-gated on
    readme.txt, and reported as a separate 'dependent' finding with its own version.
    """
    core_repo, plugin_repo = core_with_plugin
    core = Project(
        name="core",
        repo_url=str(core_repo.path),
        public_paths=["assets"],
        probe_files=["assets/core.js"],
        banners=BannerSpec(paths=[{"path": "assets/core.js", "match": "CORE-"}]),
        dependents={"projects": ["myplugin"]},
    )
    plugin = Project(
        name="myplugin",
        repo_url=str(plugin_repo.path),
        served_prefix="wp-content/plugins/myplugin",
        public_paths=["assets"],
        probe_files=["assets/app.js"],
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(core, settings=settings, storage=store)
    await index_project(plugin, settings=settings, storage=store)

    # Deployment: core at root + the plugin (v2.0) served under wp-content/plugins/myplugin.
    serve_dir = tmp_path / "deploy"
    (serve_dir / "assets").mkdir(parents=True)
    (serve_dir / "assets" / "core.js").write_text("CORE-2")
    pdir = serve_dir / "wp-content" / "plugins" / "myplugin"
    (pdir / "assets").mkdir(parents=True)
    (pdir / "assets" / "app.js").write_text("PL-2")
    (pdir / "readme.txt").write_text("Stable tag: 2.0\n")  # presence marker

    httpd, url = _serve(serve_dir)
    try:
        result = await scan_target(
            url, software="core", settings=settings, storage=store,
            registry=Registry({"core": core, "myplugin": plugin}),
            with_dependents=True, concurrency=2,
        )
    finally:
        httpd.shutdown()
        await store.close()

    by_software = {f.software: f for f in result.findings}
    assert "core" in by_software and by_software["core"].version == "v2.0"
    assert "myplugin" in by_software, "dependent plugin was not detected"
    pf = by_software["myplugin"]
    assert pf.detected_by == "dependent"
    assert pf.version == "v2.0"
    assert pf.commit_sha == plugin_repo.tag_to_sha["v2.0"]


@pytest.mark.asyncio
async def test_scan_autodetects_by_banner(fake_repo, tmp_path) -> None:
    project = Project(
        name="fake",
        repo_url=str(fake_repo.path),
        public_paths=["public"],
        probe_files=["public/app.js", "public/lib.js"],
        banners=BannerSpec(paths=[{"path": "public/app.js", "match": "APP-"}]),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    await index_project(project, settings=settings, storage=store)

    serve_dir = tmp_path / "deploy"
    serve_dir.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(fake_repo.path), "archive", "v2.0"],
        capture_output=True,
        check=True,
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(serve_dir)], input=archive, check=True)

    httpd, url = _serve(serve_dir)
    try:
        result = await scan_target(
            url,
            settings=settings,  # no software -> banner auto-detection
            storage=store,
            registry=Registry({"fake": project}),
            with_dependents=False,
        )
    finally:
        httpd.shutdown()
        await store.close()

    assert result.error is None
    assert result.findings[0].detected_by == "banner"
    assert result.findings[0].commit_sha == fake_repo.tag_to_sha["v2.0"]
