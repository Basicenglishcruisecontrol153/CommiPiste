"""Active version probing: off by default (explicit notice), extracts version when enabled."""

from __future__ import annotations

import functools
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from CommiPiste.config import get_settings
from CommiPiste.detector.scan import scan_target
from CommiPiste.models import BannerSpec, Project, VersionProbe
from CommiPiste.registry.loader import Registry
from CommiPiste.storage import open_storage


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        # Emulate a Mattermost-like server: version header on every response, open ping endpoint.
        self.send_response(200)
        self.send_header("X-Version-Id", "11.9.0.27667462323.abc123.true")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>chat</body></html>")


def _serve():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


def _project() -> Project:
    return Project(
        name="chatapp",
        repo_url="https://github.com/example/chatapp",
        banners=BannerSpec(headers={"X-Version-Id": r"\d+\.\d+\.\d+"}),
        version_probe=VersionProbe(
            paths=["/api/v4/system/ping"], header="X-Version-Id", regex=r"^(\d+\.\d+\.\d+)"
        ),
    )


async def _scan(tmp_path, *, active: bool):
    project = _project()
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    httpd, url = _serve()
    try:
        return await scan_target(
            url, settings=settings, storage=store, registry=Registry({"chatapp": project}),
            with_dependents=False, active_probe=active,
        )
    finally:
        httpd.shutdown()
        await store.close()


@pytest.mark.asyncio
async def test_off_by_default_emits_explicit_notice(tmp_path) -> None:
    result = await _scan(tmp_path, active=False)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.software == "chatapp"
    assert f.needs_active_probe is True       # explicit: caller must opt in
    assert f.version is None                  # not extracted without --active


@pytest.mark.asyncio
async def test_active_extracts_version(tmp_path) -> None:
    result = await _scan(tmp_path, active=True)
    f = result.findings[0]
    assert f.detected_by == "active"
    assert f.version == "11.9.0"
    assert f.needs_active_probe is False
    assert f.confidence.exact is True


class _RpcHandler(BaseHTTPRequestHandler):
    """Emulates a JSON-RPC version endpoint (Zabbix-style apiinfo.version)."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"jsonrpc":"2.0","result":"5.0.43","id":1}')


@pytest.mark.asyncio
async def test_active_post_jsonrpc(tmp_path) -> None:
    """version_probe via POST + JSON body (Zabbix apiinfo.version) extracts the version."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RpcHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    project = Project(
        name="zbx", repo_url="https://github.com/zabbix/zabbix",
        banners=BannerSpec(body_regex=["zbx"]),
        version_probe=VersionProbe(
            paths=["/api_jsonrpc.php"], method="POST",
            body='{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}',
            content_type="application/json-rpc", regex=r'"result"\s*:\s*"([0-9.]+)"',
        ),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    try:
        result = await scan_target(
            url, software="zbx", settings=settings, storage=store,
            registry=Registry({"zbx": project}), with_dependents=False, active_probe=True,
        )
    finally:
        httpd.shutdown()
        await store.close()
    f = result.findings[0]
    assert f.detected_by == "active" and f.version == "5.0.43"


class _MultiFieldHandler(BaseHTTPRequestHandler):
    """Emulates an API that returns the version split across fields (Immich /api/server/version)."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"major":2,"minor":7,"patch":5}')


@pytest.mark.asyncio
async def test_active_version_template_composes_fields(tmp_path) -> None:
    """version_template assembles the version from multiple regex groups (e.g. 2.7.5)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MultiFieldHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    project = Project(
        name="imm", repo_url="https://github.com/immich-app/immich",
        banners=BannerSpec(body_regex=["major"]),
        version_probe=VersionProbe(
            paths=["/api/server/version"],
            regex=r'"major":(\d+),"minor":(\d+),"patch":(\d+)', version_template="{0}.{1}.{2}",
        ),
    )
    settings = get_settings(home=tmp_path / "home")
    store = await open_storage(settings.db_path)
    try:
        result = await scan_target(
            url, software="imm", settings=settings, storage=store,
            registry=Registry({"imm": project}), with_dependents=False, active_probe=True,
        )
    finally:
        httpd.shutdown()
        await store.close()
    assert result.findings[0].version == "2.7.5"


@pytest.mark.asyncio
async def test_resolve_tag_commit_from_local_repo(fake_repo) -> None:
    """Infer a commit from a version by matching the repo's release tag (git ls-remote)."""
    from CommiPiste.detector.active import resolve_tag_commit

    # fake_repo is a real local git repo with tags v1.0/v1.1/v2.0 (conftest).
    sha = await resolve_tag_commit(str(fake_repo.path), "1.1")  # normalized match to tag v1.1
    assert sha == fake_repo.tag_to_sha["v1.1"]
    assert await resolve_tag_commit(str(fake_repo.path), "9.9.9") is None  # no such tag
