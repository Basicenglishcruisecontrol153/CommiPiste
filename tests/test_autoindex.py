"""--autoindex: an unknown target gives its repo via --repo; the tool clones, auto-detects public
dirs from the registry's known names, indexes release tags into the live DB, then fingerprints."""

from __future__ import annotations

import functools
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.scan import _adhoc_project, _known_public_dirs, scan_target
from CommiPiste.models import Project
from CommiPiste.registry.loader import Registry, load_registry
from CommiPiste.storage import open_storage


def test_adhoc_project_derives_name() -> None:
    p = _adhoc_project("https://github.com/Org/MyApp.git", public=["public", "img"])
    assert p is not None and p.name == "myapp" and p.public_paths == ["public", "img"]
    assert _adhoc_project(None) is None  # no repo -> nothing to index


def test_known_public_dirs_ranks_by_frequency() -> None:
    reg = Registry({
        "a": Project(name="a", repo_url="r", public_paths=["js", "css"]),
        "b": Project(name="b", repo_url="r", public_paths=["js", "themes"]),
        "c": Project(name="c", repo_url="r", public_paths=["js"]),
    })
    # "js" (3) before "css"/"themes" (1 each); only the top segment is kept.
    assert _known_public_dirs(reg)[0] == "js"
    assert set(_known_public_dirs(reg)) == {"js", "css", "themes"}


def _serve(directory: Path):
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.mark.asyncio
async def test_autoindex_autodetects_public_then_fingerprints(fake_repo, tmp_path) -> None:
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)  # empty DB: nothing indexed yet

    # Serve a checkout of v2.0 as the live deployment.
    serve_dir = tmp_path / "deploy"
    serve_dir.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(fake_repo.path), "archive", "v2.0"], capture_output=True, check=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(serve_dir)], input=archive, check=True)
    httpd, url = _serve(serve_dir)

    # Registry is otherwise unrelated, but it tells autoindex that "public" is a known public dir.
    registry = Registry({"other": Project(name="other", repo_url="x", public_paths=["public"])})
    try:
        result = await scan_target(
            url,
            settings=settings,
            storage=store,
            registry=registry,
            with_dependents=False,
            autoindex=True,
            repo_url=str(fake_repo.path),  # not in the registry -> ad-hoc; public auto-detected
        )

        assert result.error is None
        f = result.findings[0]
        assert f.detected_by == "autoindex"
        assert f.confidence.exact
        assert f.commit_sha == fake_repo.tag_to_sha["v2.0"]
        assert f.version == "v2.0"

        # Second run: a plain scan (no --autoindex, no --repo) now detects it. The project was
        # persisted to the local registry, and fingerprint detection identifies it without a banner.
        again = await scan_target(
            url,
            settings=settings,
            storage=store,
            registry=load_registry(settings),  # reloads the persisted local project
            with_dependents=False,
        )
    finally:
        httpd.shutdown()
        await store.close()

    assert again.error is None
    g = again.findings[0]
    assert g.detected_by == "fingerprint"
    assert g.commit_sha == fake_repo.tag_to_sha["v2.0"]
