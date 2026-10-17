# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import http.client
import io
import json
import os
import socket
import stat
import time
import urllib.error
import urllib.request
import urllib.response
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
import refresh_frameworks as refresh
from lib import audit, fetch

CATALOG = {"catalog": {"uuid": "x", "metadata": {"title": "SP 800-53", "version": "5.2.0"}}}
CATALOG_BYTES = json.dumps(CATALOG).encode()
CSF = {"catalog": {"uuid": "y", "metadata": {"title": "CSF", "version": "2.0"}}}
CSF_BYTES = json.dumps(CSF).encode()
NIST = refresh.ADAPTERS["nist-800-53"]
NIST_URL = NIST.files[0][0]
CSF_URL = refresh.ADAPTERS["nist-csf-2.0"].files[0][0]
MANIFEST_KEYS = {"file", "sha256", "version", "pinned_on", "source_url", "upstream_ref", "license"}
Route = tuple[int, bytes | Exception, dict[str, str]]


class _RaisingBody(io.BytesIO):
    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self.exc = exc

    def read(self, *args: object) -> bytes:
        raise self.exc


class FakeWeb:
    def __init__(self) -> None:
        self.routes: dict[str, Route | Exception] = {
            NIST_URL: (200, CATALOG_BYTES, {}),
            CSF_URL: (200, CSF_BYTES, {}),
        }
        self.requests: list[urllib.request.Request] = []
        self.reasons: dict[str, str] = {}

    def open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        self.requests.append(req)
        route = self.routes.get(req.full_url)
        if route is None:
            raise AssertionError(f"unexpected request {req.full_url}")
        if isinstance(route, Exception):
            raise route
        code, body, extra = route
        headers = Message()
        for key, value in extra.items():
            headers[key] = value
        fp = _RaisingBody(body) if isinstance(body, Exception) else io.BytesIO(body)
        resp = urllib.response.addinfourl(fp, headers, req.full_url, code)
        resp.msg = self.reasons.get(req.full_url, "fake")
        return resp


@pytest.fixture
def web(monkeypatch: pytest.MonkeyPatch) -> FakeWeb:
    # 0026: handler-level fake so the redirect rules in lib.fetch still run; sockets refuse.
    fake = FakeWeb()
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", lambda _h, req: fake.open(req))
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", lambda _h, req: fake.open(req))

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("real network call")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    return fake


def _main(*args: str) -> int:
    return refresh.main(["--only", "nist-800-53", *args])


def _nist(root: Path) -> Path:
    return root / "frameworks" / "nist"


def _files(dest: Path) -> list[str]:
    return sorted(p.name for p in dest.iterdir() if p.name != fetch.LOCK)


def _manifest(dest: Path) -> list[dict[str, Any]]:
    return json.loads((dest / "manifest.json").read_text(encoding="utf-8"))


def _entry(dest: Path, name: str = "catalog.json") -> dict[str, Any]:
    return next(e for e in _manifest(dest) if e["file"] == name)


def _with(monkeypatch: pytest.MonkeyPatch, **changes: Any) -> None:
    adapter = dataclasses.replace(NIST, **changes)
    monkeypatch.setitem(refresh.ADAPTERS, "nist-800-53", adapter)


def _with_url(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _with(monkeypatch, files=((url, "catalog.json"),))


def test_manifest_fields_and_sha256(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = _nist(tmp_path)
    assert _main("--cache-root", str(tmp_path)) == 0
    digest = hashlib.sha256(CATALOG_BYTES).hexdigest()
    assert (dest / "catalog.json").read_bytes() == CATALOG_BYTES
    raw = (dest / "manifest.json").read_text(encoding="utf-8")
    assert raw.endswith("]\n")
    manifest = json.loads(raw)
    assert raw == json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    assert manifest == [
        {
            "file": "catalog.json",
            "license": "public domain (17 U.S.C. 105)",
            "pinned_on": datetime.now(UTC).date().isoformat(),
            "sha256": digest,
            "source_url": NIST_URL,
            "upstream_ref": "v1.5.0",
            "version": "5.2.0",
        }
    ]
    out = capsys.readouterr().out
    assert out == f"pinned nist-800-53 5.2.0 sha256={digest} at {dest / 'catalog.json'}\n"
    assert _files(dest) == ["catalog.json", "manifest.json"]


def test_requests_carry_headers_and_timeout(web: FakeWeb, tmp_path: Path) -> None:
    assert _main("--cache-root", str(tmp_path)) == 0
    assert [r.full_url for r in web.requests] == [NIST_URL]
    req = web.requests[0]
    assert req.timeout == 60
    assert req.get_header("User-agent") == "daedalus-refresh"
    assert req.get_header("Accept") == "application/json"


def test_redirect_to_another_host_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = (302, b"", {"Location": "https://evil.example.com/c"})
    assert _main("--cache-root", str(tmp_path)) == 1
    err = capsys.readouterr().err
    assert "redirect to evil.example.com refused." in err
    assert "Next: check the source URL; redirects off GitHub are refused." in err
    assert _files(_nist(tmp_path)) == []
    assert [r.full_url for r in web.requests] == [NIST_URL]


def test_redirect_to_plain_http_on_github_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[NIST_URL] = (301, b"", {"Location": "http://github.com/c"})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert len(web.requests) == 1


def test_redirect_within_github_is_followed(web: FakeWeb, tmp_path: Path) -> None:
    moved = "https://github.com/usnistgov/oscal-content/raw/v1.5.0/catalog.json"
    web.routes[NIST_URL] = (302, b"", {"Location": moved})
    web.routes[moved] = (200, CATALOG_BYTES, {})
    assert _main("--cache-root", str(tmp_path)) == 0
    assert (_nist(tmp_path) / "catalog.json").read_bytes() == CATALOG_BYTES


def test_dest_defaults_under_the_cache_dir(web: FakeWeb, plugin_data: Path) -> None:
    assert _main() == 0
    dest = _nist(plugin_data.resolve())
    assert _entry(dest)["sha256"] == hashlib.sha256(CATALOG_BYTES).hexdigest()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700


def test_cache_root_flag_is_honored(web: FakeWeb, plugin_data: Path, tmp_path: Path) -> None:
    root = tmp_path / "elsewhere"
    assert _main("--cache-root", str(root)) == 0
    assert (_nist(root) / "manifest.json").is_file()
    assert not (plugin_data / "frameworks").exists()


def test_no_cache_dir_exits_one_with_next(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert _main() == 1
    assert capsys.readouterr().err == audit.NO_CACHE + "\n"
    assert web.requests == []


def test_oversize_response_is_refused(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(fetch, "MAX_BYTES", len(CATALOG_BYTES) - 1)
    monkeypatch.setattr(fetch, "CHUNK", 7)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert "response exceeds" in capsys.readouterr().err
    assert _files(_nist(tmp_path)) == []


def test_response_at_the_cap_is_accepted(
    web: FakeWeb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetch, "MAX_BYTES", len(CATALOG_BYTES))
    assert _main("--cache-root", str(tmp_path)) == 0


def test_non_json_catalog_is_refused_and_leaves_nothing(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = (200, b"<html>not json</html>", {})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert "nist-800-53: catalog is not valid JSON. Next:" in capsys.readouterr().err
    assert _files(_nist(tmp_path)) == []


def test_missing_version_key_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = json.dumps({"catalog": {"metadata": {"title": "no version"}}}).encode()
    web.routes[NIST_URL] = (200, body, {})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert "catalog has no catalog.metadata.version key. Next:" in capsys.readouterr().err
    assert _files(_nist(tmp_path)) == []


def test_top_level_metadata_version_is_the_fallback(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[NIST_URL] = (200, json.dumps({"metadata": {"version": "5.1.1"}}).encode(), {})
    assert _main("--cache-root", str(tmp_path)) == 0
    assert _entry(_nist(tmp_path))["version"] == "5.1.1"


def test_version_with_control_characters_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    body = json.dumps({"catalog": {"metadata": {"version": "5\x1b[2J"}}}).encode()
    web.routes[NIST_URL] = (200, body, {})
    assert _main("--cache-root", str(tmp_path)) == 1


def test_upstream_ref_is_the_pinned_tag_without_an_api_call(web: FakeWeb, tmp_path: Path) -> None:
    # 0026: the pin replaces the commits API lookup; no request leaves for api.github.com.
    assert _main("--cache-root", str(tmp_path)) == 0
    assert _entry(_nist(tmp_path))["upstream_ref"] == "v1.5.0"
    assert all("api.github.com" not in r.full_url for r in web.requests)


def test_source_url_is_recorded_as_the_adapter_url(
    web: FakeWeb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fork = "https://raw.githubusercontent.com/someone/fork/v1.5.0/catalog.json"
    web.routes[fork] = (200, CATALOG_BYTES, {})
    _with_url(monkeypatch, fork)
    assert _main("--cache-root", str(tmp_path)) == 0
    assert _entry(_nist(tmp_path))["source_url"] == fork
    assert [r.full_url for r in web.requests] == [fork]


def test_redirect_off_github_on_a_rerun_keeps_the_old_pair(web: FakeWeb, tmp_path: Path) -> None:
    dest = _nist(tmp_path)
    assert _main("--cache-root", str(tmp_path)) == 0
    before = {p.name: p.read_bytes() for p in dest.iterdir()}
    web.routes[NIST_URL] = (302, b"", {"Location": "https://evil.example.com/api"})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert {p.name: p.read_bytes() for p in dest.iterdir()} == before


def test_symlinked_dest_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "frameworks").mkdir()
    link = _nist(tmp_path)
    link.symlink_to(real)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert f"{link} is a symlink. Next:" in capsys.readouterr().err
    assert list(real.iterdir()) == []
    assert web.requests == []


@pytest.mark.parametrize("name", ["catalog.json", "manifest.json"])
def test_symlinked_cache_file_is_refused(web: FakeWeb, tmp_path: Path, name: str) -> None:
    dest = _nist(tmp_path)
    dest.mkdir(parents=True)
    target = tmp_path / "target"
    target.write_text("keep", encoding="utf-8")
    (dest / name).symlink_to(target)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert target.read_text(encoding="utf-8") == "keep"
    assert web.requests == []


URL_NEXT = "Next: report this line; the adapter URLs are pinned in refresh_frameworks.py."


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/usnistgov/oscal-content/v1.5.0/x.json",
        "https://example.com/x.json",
        "https://raw.githubusercontent.com.evil.example/x.json",
        "https://raw.githubusercontent.com:8443/x.json",
        "file:///etc/passwd",
    ],
)
def test_source_url_off_https_github_is_refused(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    url: str,
) -> None:
    _with_url(monkeypatch, url)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert URL_NEXT in capsys.readouterr().err
    assert web.requests == []


@pytest.mark.parametrize(
    "argv", [["--cache-root"], ["--cache-roo", "x"], ["--bogus"], ["--only"], ["--dest", "x"]]
)
def test_usage_errors_exit_one_with_next(
    web: FakeWeb, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        refresh.main(argv)
    assert exc.value.code == 1
    assert "Next: run with --help for the options." in capsys.readouterr().err


def test_cache_dir_or_probe_prefers_the_env(
    plugin_data: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / ".claude" / "plugins" / "data" / "daedalus-acme").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    assert audit.cache_dir_or_probe() == plugin_data.resolve()


@pytest.mark.parametrize("env", [None, ""])
def test_cache_dir_or_probe_falls_back_to_the_first_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env: str | None
) -> None:
    if env is None:
        monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    else:
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", env)
    base = tmp_path / "home" / ".claude" / "plugins" / "data"
    (base / "daedalus-inline").mkdir(parents=True)
    (base / "daedalus-acme").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert audit.cache_dir_or_probe() == (base / "daedalus-acme").resolve()


def test_cache_dir_or_probe_raises_with_next_when_nothing_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    with pytest.raises(RuntimeError) as exc:
        audit.cache_dir_or_probe()
    assert str(exc.value) == (
        "no plugin cache dir found. Next: run /daedalus:doctor inside Claude Code once so the "
        "plugin data directory exists."
    )


UPPER_URL = NIST_URL.replace(
    "https://raw.githubusercontent.com", "HTTPS://RAW.GITHUBUSERCONTENT.COM"
)


def test_incomplete_catalog_body_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = (200, http.client.IncompleteRead(b"", 100), {})
    assert _main("--cache-root", str(tmp_path)) == 1
    err = capsys.readouterr().err
    assert err.startswith("nist-800-53: download failed: IncompleteRead")
    assert "Next: check your network and the source URL" in err
    assert _files(_nist(tmp_path)) == []


def test_bad_status_line_on_the_catalog_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = http.client.BadStatusLine("garbage")
    assert _main("--cache-root", str(tmp_path)) == 1
    assert "download failed: garbage. Next:" in capsys.readouterr().err
    assert _files(_nist(tmp_path)) == []


def test_unexpected_error_exits_one_with_next(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def boom(raw: bytes) -> str:
        raise ZeroDivisionError("x\x1b")

    _with(monkeypatch, version=boom)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert capsys.readouterr().err == (
        "nist-800-53: refresh failed: ZeroDivisionError: x?. "
        "Next: run the script again; if it repeats, report this line.\n"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com/a b.json",
        "https://raw.githubusercontent.com/a\nb.json",
        "https://raw.githubusercontent.com/a\tb.json",
        "https://raw.githubusercontent.com/a\x7fb.json",
        "https://evil.example@raw.githubusercontent.com/x.json",
        "https://user:pw@raw.githubusercontent.com/x.json",
        "https://raw.githubusercontent.com/x.json?token=1",
        "https://raw.githubusercontent.com/x.json?",
        "https://raw.githubusercontent.com/x.json#frag",
        "https://raw.githubusercontent.com/a/../b.json",
        "https://raw.githubusercontent.com/a/./b.json",
        "https://raw.githubusercontent.com/a/%2e%2e/b.json",
        "https://raw.githubusercontent.com/a/..",
        "https://raw.githubusercontent.com/a\\..\\b.json",
        "https://raw.githubusercontent.com/a/..%2f..%2fb.json",
        "https://raw.githubusercontent.com/a/..%2F..%2Fb.json",
        "https://raw.githubusercontent.com/a/..%5c..%5cb.json",
        "https://raw.githubusercontent.com/a/..%5C..%5Cb.json",
        "https://raw.githubusercontent.com/caf\u00e9.json",
        "https://api.github.com/repos/x/commits?path=a",
    ],
)
def test_source_url_with_unsafe_parts_is_refused_before_dest(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    url: str,
) -> None:
    _with_url(monkeypatch, url)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert URL_NEXT in capsys.readouterr().err
    assert not (tmp_path / "frameworks").exists()
    assert web.requests == []


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example@raw.githubusercontent.com/x.json",
        "https://raw.githubusercontent.com/x.json?token=1",
        "https://raw.githubusercontent.com/x.json#frag",
        "https://raw.githubusercontent.com/a/../b.json",
        "https://raw.githubusercontent.com/a/%2e%2e/b.json",
        "https://raw.githubusercontent.com/a\\b.json",
        "https://raw.githubusercontent.com/a%2fb.json",
        "https://raw.githubusercontent.com/a%5Cb.json",
        "http://raw.githubusercontent.com/b.json",
    ],
)
def test_redirect_with_unsafe_parts_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    web.routes[NIST_URL] = (302, b"", {"Location": target})
    assert _main("--cache-root", str(tmp_path)) == 1
    err = capsys.readouterr().err
    rules = "redirect to raw.githubusercontent.com breaks the URL rules."
    assert f"{rules} {fetch.RULES_NEXT}" in err
    assert "off GitHub" not in err
    assert len(web.requests) == 1
    assert _files(_nist(tmp_path)) == []


def test_api_rename_redirect_with_a_query_is_followed(web: FakeWeb, tmp_path: Path) -> None:
    # R1-m2: the query exception for api.github.com redirects survives the move to lib.fetch.
    moved = "https://api.github.com/repositories/1/contents/catalog.json?ref=v1.5.0"
    web.routes[NIST_URL] = (301, b"", {"Location": moved})
    web.routes[moved] = (200, CATALOG_BYTES, {})
    assert _main("--cache-root", str(tmp_path)) == 0
    assert (_nist(tmp_path) / "catalog.json").read_bytes() == CATALOG_BYTES
    assert web.requests[-1].full_url == moved


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_unparsable_redirect_location_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], code: int
) -> None:
    web.routes[NIST_URL] = (code, b"", {"Location": "https://[oops/x"})
    assert _main("--cache-root", str(tmp_path)) == 1
    err = capsys.readouterr().err
    assert "redirect Location is not a valid URL: " in err
    assert err.endswith(f"{fetch.REDIRECT_NEXT}\n")
    assert _files(_nist(tmp_path)) == []


def test_value_error_in_download_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = ValueError("bad url")
    assert _main("--cache-root", str(tmp_path)) == 1
    assert capsys.readouterr().err == (
        "nist-800-53: download failed: bad url. Next: check the source URL and its redirects.\n"
    )


@pytest.mark.parametrize(("length", "code"), [(64, 0), (65, 1)])
def test_version_length_cap_is_64(web: FakeWeb, tmp_path: Path, length: int, code: int) -> None:
    body = json.dumps({"catalog": {"metadata": {"version": "v" * length}}}).encode()
    web.routes[NIST_URL] = (200, body, {})
    assert _main("--cache-root", str(tmp_path)) == code
    if code == 0:
        assert _entry(_nist(tmp_path))["version"] == "v" * length


def test_dest_that_is_a_file_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = _nist(tmp_path)
    dest.parent.mkdir()
    dest.write_text("x", encoding="utf-8")
    assert _main("--cache-root", str(tmp_path)) == 1
    assert capsys.readouterr().err == (
        f"nist-800-53: {dest} is not a directory. Next: move it aside; the cache needs a "
        "directory there.\n"
    )
    assert web.requests == []


def test_dest_walk_starts_at_the_first_existing_ancestor(web: FakeWeb, tmp_path: Path) -> None:
    # M5: an operator's own symlinked ancestor of the cache root is followed.
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    assert _main("--cache-root", str(tmp_path / "link" / "a")) == 0
    assert (_nist(real / "a") / "catalog.json").read_bytes() == CATALOG_BYTES
    assert stat.S_IMODE((real / "a").stat().st_mode) == 0o700


def test_uppercase_scheme_and_host_are_allowed(
    web: FakeWeb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    web.routes[UPPER_URL] = (200, CATALOG_BYTES, {})
    _with_url(monkeypatch, UPPER_URL)
    assert _main("--cache-root", str(tmp_path)) == 0
    assert _entry(_nist(tmp_path))["source_url"] == UPPER_URL


def test_invalid_inner_version_is_not_masked_by_the_top_level_one(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = {"catalog": {"metadata": {"version": "5\n"}}, "metadata": {"version": "1.0"}}
    web.routes[NIST_URL] = (200, json.dumps(body).encode(), {})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert capsys.readouterr().err.startswith(
        "nist-800-53: catalog.metadata.version is not a printable string of 64 characters or "
        "fewer. Next:"
    )
    assert _files(_nist(tmp_path)) == []


def test_invalid_top_level_version_names_its_key(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = (200, b'{"metadata": {"version": 5}}', {})
    assert _main("--cache-root", str(tmp_path)) == 1
    assert capsys.readouterr().err.startswith(
        "nist-800-53: metadata.version is not a printable string"
    )


def test_held_lock_exits_one_within_the_bound(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(fetch, "LOCK_TIMEOUT_S", 0.2)
    dest = _nist(tmp_path)
    dest.mkdir(parents=True)
    with open(dest / fetch.LOCK, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        assert _main("--cache-root", str(tmp_path)) == 1
        assert time.monotonic() - started < 5
    err = capsys.readouterr().err
    assert err.startswith("nist-800-53: refresh lock held for 0.2 s")
    assert "Next: wait for the other refresh to finish" in err
    assert web.requests == []
    assert _files(dest) == []


def test_symlinked_lock_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    dest = _nist(tmp_path)
    dest.mkdir(parents=True)
    (dest / fetch.LOCK).symlink_to(tmp_path / "elsewhere.lock")
    assert _main("--cache-root", str(tmp_path)) == 1
    assert not (tmp_path / "elsewhere.lock").exists()


def test_fifo_lock_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = _nist(tmp_path)
    dest.mkdir(parents=True)
    os.mkfifo(dest / fetch.LOCK)
    assert _main("--cache-root", str(tmp_path)) == 1
    assert "is not a regular file. Next:" in capsys.readouterr().err


def test_symlinked_frameworks_dir_is_refused(
    web: FakeWeb, plugin_data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (plugin_data / "frameworks").symlink_to(elsewhere)
    assert _main() == 1
    assert "frameworks is a symlink. Next:" in capsys.readouterr().err
    assert list(elsewhere.iterdir()) == []
    assert web.requests == []


def test_created_parents_are_0700(web: FakeWeb, plugin_data: Path, tmp_path: Path) -> None:
    assert _main() == 0
    for path in (plugin_data / "frameworks", _nist(plugin_data)):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
    deep = tmp_path / "a" / "b" / "c"
    assert _main("--cache-root", str(deep)) == 0
    for path in (tmp_path / "a", tmp_path / "a" / "b", deep, deep / "frameworks", _nist(deep)):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path


def test_server_reason_is_masked(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[NIST_URL] = (404, b"", {})
    web.reasons[NIST_URL] = "Not \x1b[31mFound"
    assert _main("--cache-root", str(tmp_path)) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "download failed: HTTP Error 404: Not ?[31mFound. Next:" in err


def test_lock_open_refuses_a_symlink_itself(tmp_path: Path) -> None:
    # M4: O_NOFOLLOW holds even when the symlink appears after the dest checks.
    (tmp_path / fetch.LOCK).symlink_to(tmp_path / "elsewhere.lock")
    with pytest.raises(fetch.RefreshError, match="is a symlink. Next:"):
        with fetch._locked(tmp_path):
            pass
    assert not (tmp_path / "elsewhere.lock").exists()


def test_created_dirs_are_0700_under_a_strict_umask(web: FakeWeb, plugin_data: Path) -> None:
    old = os.umask(0o277)
    try:
        assert _main() == 0
    finally:
        os.umask(old)
    for path in (plugin_data / "frameworks", _nist(plugin_data)):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path


def test_manifest_is_a_list_with_the_0026_keys(web: FakeWeb, tmp_path: Path) -> None:
    assert refresh.main(["--only", "nist-800-53,nist-csf-2.0", "--cache-root", str(tmp_path)]) == 0
    manifest = _manifest(_nist(tmp_path))
    assert isinstance(manifest, list)
    assert [e["file"] for e in manifest] == ["catalog.json", "csf-2.0.json"]
    for entry in manifest:
        assert set(entry) == MANIFEST_KEYS
    csf = _entry(_nist(tmp_path), "csf-2.0.json")
    assert csf["version"] == "2.0"
    assert csf["sha256"] == hashlib.sha256(CSF_BYTES).hexdigest()


def test_a_legacy_dict_manifest_is_replaced_by_the_list(web: FakeWeb, tmp_path: Path) -> None:
    dest = _nist(tmp_path)
    dest.mkdir(parents=True)
    (dest / "manifest.json").write_text('{"catalog_file": "catalog.json"}', encoding="utf-8")
    assert _main("--cache-root", str(tmp_path)) == 0
    assert [e["file"] for e in _manifest(dest)] == ["catalog.json"]


def test_nist_adapters_pin_v1_5_0() -> None:
    raw = "https://raw.githubusercontent.com/usnistgov/oscal-content/v1.5.0/nist.gov/"
    nist = refresh.ADAPTERS["nist-800-53"]
    csf = refresh.ADAPTERS["nist-csf-2.0"]
    assert nist.ref == csf.ref == "v1.5.0"
    assert nist.family == csf.family == "nist"
    assert nist.files == (
        (raw + "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json", "catalog.json"),
    )
    assert csf.files == ((raw + "CSF/v2.0/json/NIST_CSF_v2.0_catalog.json", "csf-2.0.json"),)
    assert nist.license == csf.license == "public domain (17 U.S.C. 105)"
    for adapter in refresh.ADAPTERS.values():
        assert all(fetch._allowed(url) for url, _ in adapter.files), adapter.name


def test_only_runs_the_named_adapters(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert refresh.main(["--only", "nist-csf-2.0", "--cache-root", str(tmp_path)]) == 0
    assert [r.full_url for r in web.requests] == [CSF_URL]
    assert _files(_nist(tmp_path)) == ["csf-2.0.json", "manifest.json"]
    assert capsys.readouterr().out.startswith("pinned nist-csf-2.0 2.0 sha256=")


def test_unknown_adapter_name_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert refresh.main(["--only", "nist-800-53,iso", "--cache-root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("unknown adapter iso. Next: pick an adapter name from ")
    assert "nist-800-53" in err
    assert web.requests == []


def test_a_failed_adapter_keeps_its_old_files(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    both = ["--only", "nist-800-53,nist-csf-2.0", "--cache-root", str(tmp_path)]
    dest = _nist(tmp_path)
    assert refresh.main(both) == 0
    old_catalog = (dest / "catalog.json").read_bytes()
    old_entry = _entry(dest)
    new_csf = json.dumps({"catalog": {"metadata": {"version": "2.1"}}}).encode()
    web.routes[NIST_URL] = (200, b"not json", {})
    web.routes[CSF_URL] = (200, new_csf, {})
    capsys.readouterr()
    assert refresh.main(both) == 1
    assert (dest / "catalog.json").read_bytes() == old_catalog
    assert _entry(dest) == old_entry
    assert (dest / "csf-2.0.json").read_bytes() == new_csf
    assert _entry(dest, "csf-2.0.json")["version"] == "2.1"
    captured = capsys.readouterr()
    assert "nist-800-53: catalog is not valid JSON. Next:" in captured.err
    assert "pinned nist-csf-2.0 2.1" in captured.out


ASVS = refresh.ADAPTERS["owasp-asvs"]
ASVS_URL = ASVS.files[0][0]
TOP10 = refresh.ADAPTERS["owasp-top10"]
ASVS_DOC = {
    "Name": "Application Security Verification Standard Project",
    "ShortName": "ASVS",
    "Version": "5.0.0",
    "Description": "fixture",
    "Requirements": [{"Shortcode": "V1", "Name": "Encoding and Sanitization"}],
}
OWASP_LICENSE = "CC BY-SA 4.0"


def _top10_body(url: str, heading: str | None = None) -> bytes:
    code = url.rsplit("/", 1)[1][:3]
    title = url.rsplit("-", 1)[1].removesuffix(".md").replace("_", " ")
    line = heading if heading is not None else f"# {code}:2025 \u2013 {title}"
    return f"---\nicon: x\n---\n\n{line}\n\n## Background\n\ntext\n".encode()


def _owasp_routes(web: FakeWeb) -> None:
    web.routes[ASVS_URL] = (200, json.dumps(ASVS_DOC).encode(), {})
    for url, _ in TOP10.files:
        web.routes[url] = (200, _top10_body(url), {})


def _owasp(root: Path) -> Path:
    return root / "frameworks" / "owasp"


def test_owasp_adapters_pin_their_refs() -> None:
    assert ASVS.ref == "v5.0.0_release"
    assert ASVS.files == (
        (
            "https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/docs_en/"
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.json",
            "asvs-5.0.0.json",
        ),
    )
    sha = "3a31f35346c3f4e90f350395124382fa53af2afe"
    assert TOP10.ref == sha
    assert len(TOP10.files) == 10
    base = f"https://raw.githubusercontent.com/OWASP/Top10/{sha}/2025/docs/en/"
    for n, (url, local) in enumerate(TOP10.files, 1):
        assert url == base + local
        assert local.startswith(f"A{n:02d}_2025-") and local.endswith(".md")
    assert TOP10.output == "top10-2025.json"
    assert ASVS.family == TOP10.family == "owasp"


def test_asvs_adapter_shape_check(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _owasp_routes(web)
    assert refresh.main(["--only", "owasp-asvs", "--cache-root", str(tmp_path)]) == 0
    raw = json.dumps(ASVS_DOC).encode()
    assert (_owasp(tmp_path) / "asvs-5.0.0.json").read_bytes() == raw
    entry = _entry(_owasp(tmp_path), "asvs-5.0.0.json")
    assert entry["version"] == "5.0.0"
    assert entry["upstream_ref"] == "v5.0.0_release"
    assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
    assert capsys.readouterr().out.startswith("pinned owasp-asvs 5.0.0 sha256=")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"Requirements": None}, "ASVS file has no Requirements list."),
        ({"Requirements": []}, "ASVS file has no Requirements list."),
        ({"Name": None}, "ASVS file lacks Name."),
        ({"Version": "5\x1b"}, "Version is not a printable string"),
    ],
)
def test_asvs_refuses_a_file_without_requirements(
    web: FakeWeb,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: dict[str, Any],
    message: str,
) -> None:
    doc = {k: v for k, v in {**ASVS_DOC, **change}.items() if v is not None}
    web.routes[ASVS_URL] = (200, json.dumps(doc).encode(), {})
    assert refresh.main(["--only", "owasp-asvs", "--cache-root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith(f"owasp-asvs: {message}")
    assert "Next:" in err
    assert _files(_owasp(tmp_path)) == []


def test_top10_compiles_ten_entries(web: FakeWeb, tmp_path: Path) -> None:
    _owasp_routes(web)
    first, second = TOP10.files[0][0], TOP10.files[1][0]
    web.routes[first] = (
        200,
        _top10_body(first, '# ![icon](a.png){: style="h"}  A01:2025 Broken Access Control'),
        {},
    )
    heading = '# A02:2025 Security Misconfiguration ![icon](b.png){: style="h"}'
    web.routes[second] = (200, _top10_body(second, heading), {})
    assert refresh.main(["--only", "owasp-top10", "--cache-root", str(tmp_path)]) == 0
    raw = (_owasp(tmp_path) / "top10-2025.json").read_bytes()
    compiled = json.loads(raw)
    assert [e["id"] for e in compiled] == [f"A{n:02d}:2025" for n in range(1, 11)]
    assert compiled[0] == {
        "id": "A01:2025",
        "title": "Broken Access Control",
        "source_file": "A01_2025-Broken_Access_Control.md",
    }
    assert compiled[1]["title"] == "Security Misconfiguration"
    assert compiled[9]["title"] == "Mishandling of Exceptional Conditions"
    assert _files(_owasp(tmp_path)) == ["manifest.json", "top10-2025.json"]
    entry = _entry(_owasp(tmp_path), "top10-2025.json")
    assert entry["version"] == "2025@3a31f35"
    assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
    assert entry["source_url"].endswith("/OWASP/Top10/" + TOP10.ref + "/2025/docs/en/")


@pytest.mark.parametrize("heading", ["## A01:2025 Broken Access Control", "# A01:2025", "text"])
def test_top10_refuses_a_missing_heading(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], heading: str
) -> None:
    _owasp_routes(web)
    first = TOP10.files[0][0]
    web.routes[first] = (200, _top10_body(first, heading), {})
    assert refresh.main(["--only", "owasp-top10", "--cache-root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("owasp-top10: A01_2025-Broken_Access_Control.md has no level-one ")
    assert "Next:" in err
    assert not _owasp(tmp_path).exists() or _files(_owasp(tmp_path)) == []


def test_owasp_manifest_carries_attribution(web: FakeWeb, tmp_path: Path) -> None:
    _owasp_routes(web)
    assert refresh.main(["--only", "owasp-asvs,owasp-top10", "--cache-root", str(tmp_path)]) == 0
    manifest = _manifest(_owasp(tmp_path))
    assert [e["file"] for e in manifest] == ["asvs-5.0.0.json", "top10-2025.json"]
    projects = {
        "asvs-5.0.0.json": "OWASP Application Security Verification Standard",
        "top10-2025.json": "OWASP Top 10",
    }
    for entry in manifest:
        assert set(entry) == MANIFEST_KEYS | {"attribution"}
        assert entry["license"] == OWASP_LICENSE
        project = projects[entry["file"]]
        assert entry["attribution"] == f"OWASP Foundation, {project}, {entry['source_url']}"


def test_no_only_runs_every_adapter(web: FakeWeb, tmp_path: Path) -> None:
    _owasp_routes(web)
    assert refresh.main(["--cache-root", str(tmp_path)]) == 0
    assert len(web.requests) == 13
    assert [e["file"] for e in _manifest(_nist(tmp_path))] == ["catalog.json", "csf-2.0.json"]
    assert len(_manifest(_owasp(tmp_path))) == 2
