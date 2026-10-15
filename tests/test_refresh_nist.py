# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

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
import urllib.parse
import urllib.request
import urllib.response
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
import refresh_nist_oscal as refresh
from lib import audit

SHA = "a" * 40
CATALOG = {"catalog": {"uuid": "x", "metadata": {"title": "SP 800-53", "version": "5.2.0"}}}
CATALOG_BYTES = json.dumps(CATALOG).encode()
API_URL = (
    refresh.API_COMMITS
    + "?"
    + urllib.parse.urlencode(
        {"path": "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json", "per_page": 1}
    )
)
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
            refresh.DEFAULT_SOURCE: (200, CATALOG_BYTES, {}),
            API_URL: (200, json.dumps([{"sha": SHA}]).encode(), {}),
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
    fake = FakeWeb()
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", lambda _h, req: fake.open(req))
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", lambda _h, req: fake.open(req))

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("real network call")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    return fake


def _files(dest: Path) -> list[str]:
    return sorted(p.name for p in dest.iterdir() if p.name != refresh.LOCK)


def _manifest(dest: Path) -> dict[str, Any]:
    return json.loads((dest / "manifest.json").read_text(encoding="utf-8"))


def test_manifest_fields_and_sha256(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    digest = hashlib.sha256(CATALOG_BYTES).hexdigest()
    assert (dest / "catalog.json").read_bytes() == CATALOG_BYTES
    raw = (dest / "manifest.json").read_text(encoding="utf-8")
    assert raw.endswith("}\n")
    manifest = json.loads(raw)
    assert raw == json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    assert manifest == {
        "catalog_file": "catalog.json",
        "catalog_sha256": digest,
        "pinned_on": datetime.now(UTC).date().isoformat(),
        "revision": "5.2.0",
        "source_url": refresh.DEFAULT_SOURCE,
        "upstream_commit": SHA,
    }
    assert capsys.readouterr().out == f"pinned 5.2.0 sha256={digest} at {dest}\n"
    assert _files(dest) == ["catalog.json", "manifest.json"]


def test_requests_carry_headers_and_timeout(web: FakeWeb, tmp_path: Path) -> None:
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 0
    assert [r.full_url for r in web.requests] == [refresh.DEFAULT_SOURCE, API_URL]
    for req in web.requests:
        assert req.timeout == 60
        assert req.get_header("User-agent") == "daedalus-refresh"
    assert web.requests[1].get_header("Accept") == "application/vnd.github+json"


def test_redirect_to_another_host_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (302, b"", {"Location": "https://evil.example.com/c"})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    assert "redirect to evil.example.com refused." in err
    assert "Next: check the source URL; redirects off GitHub are refused." in err
    assert _files(dest) == []
    assert [r.full_url for r in web.requests] == [refresh.DEFAULT_SOURCE]


def test_redirect_to_plain_http_on_github_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (301, b"", {"Location": "http://github.com/c"})
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1
    assert len(web.requests) == 1


def test_redirect_within_github_is_followed(web: FakeWeb, tmp_path: Path) -> None:
    moved = "https://github.com/usnistgov/oscal-content/raw/main/catalog.json"
    web.routes[refresh.DEFAULT_SOURCE] = (302, b"", {"Location": moved})
    web.routes[moved] = (200, CATALOG_BYTES, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert (dest / "catalog.json").read_bytes() == CATALOG_BYTES


def test_dest_defaults_under_the_cache_dir(web: FakeWeb, plugin_data: Path) -> None:
    assert refresh.main([]) == 0
    dest = plugin_data.resolve() / "frameworks" / "nist"
    assert _manifest(dest)["catalog_sha256"] == hashlib.sha256(CATALOG_BYTES).hexdigest()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700


def test_dest_flag_is_honored(web: FakeWeb, plugin_data: Path, tmp_path: Path) -> None:
    dest = tmp_path / "elsewhere"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert (dest / "manifest.json").is_file()
    assert not (plugin_data / "frameworks").exists()


def test_no_cache_dir_exits_one_with_next(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert refresh.main([]) == 1
    assert capsys.readouterr().err == audit.NO_CACHE + "\n"
    assert web.requests == []


def test_oversize_response_is_refused(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(refresh, "MAX_BYTES", len(CATALOG_BYTES) - 1)
    monkeypatch.setattr(refresh, "CHUNK", 7)
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    assert "response exceeds" in capsys.readouterr().err
    assert _files(dest) == []


def test_response_at_the_cap_is_accepted(
    web: FakeWeb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(refresh, "MAX_BYTES", len(CATALOG_BYTES))
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 0


def test_non_json_catalog_is_refused_and_leaves_nothing(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (200, b"<html>not json</html>", {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    assert "catalog is not valid JSON. Next:" in capsys.readouterr().err
    assert _files(dest) == []


def test_missing_version_key_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = json.dumps({"catalog": {"metadata": {"title": "no version"}}}).encode()
    web.routes[refresh.DEFAULT_SOURCE] = (200, body, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    assert "catalog has no catalog.metadata.version key. Next:" in capsys.readouterr().err
    assert _files(dest) == []


def test_top_level_metadata_version_is_the_fallback(web: FakeWeb, tmp_path: Path) -> None:
    body = json.dumps({"metadata": {"version": "5.1.1"}}).encode()
    web.routes[refresh.DEFAULT_SOURCE] = (200, body, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["revision"] == "5.1.1"


def test_version_with_control_characters_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    body = json.dumps({"catalog": {"metadata": {"version": "5\x1b[2J"}}}).encode()
    web.routes[refresh.DEFAULT_SOURCE] = (200, body, {})
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1


@pytest.mark.parametrize("code", [403, 429])
def test_api_rate_limit_records_null(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], code: int
) -> None:
    web.routes[API_URL] = (code, b'{"message":"rate limited"}', {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] is None
    err = capsys.readouterr().err
    assert err == f"notice: upstream_commit recorded as null; GitHub API HTTP {code}.\n"


def test_api_unreachable_records_null(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[API_URL] = urllib.error.URLError("no route")
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] is None


def test_api_without_a_sha_records_null(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[API_URL] = (200, b"[]", {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] is None


def test_api_redirect_off_github_fails_and_keeps_the_old_pair(web: FakeWeb, tmp_path: Path) -> None:
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    before = {p.name: p.read_bytes() for p in dest.iterdir()}
    web.routes[refresh.DEFAULT_SOURCE] = (
        200,
        json.dumps({"metadata": {"version": "9"}}).encode(),
        {},
    )
    web.routes[API_URL] = (302, b"", {"Location": "https://evil.example.com/api"})
    assert refresh.main(["--dest", str(dest)]) == 1
    assert {p.name: p.read_bytes() for p in dest.iterdir()} == before


def test_foreign_source_records_null_without_an_api_call(web: FakeWeb, tmp_path: Path) -> None:
    fork = "https://raw.githubusercontent.com/someone/fork/main/catalog.json"
    web.routes[fork] = (200, CATALOG_BYTES, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--source-url", fork, "--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] is None
    assert _manifest(dest)["source_url"] == fork
    assert [r.full_url for r in web.requests] == [fork]


def test_symlinked_dest_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "nist"
    link.symlink_to(real)
    assert refresh.main(["--dest", str(link)]) == 1
    assert f"{link} is a symlink. Next:" in capsys.readouterr().err
    assert list(real.iterdir()) == []
    assert web.requests == []


@pytest.mark.parametrize("name", ["catalog.json", "manifest.json"])
def test_symlinked_cache_file_is_refused(web: FakeWeb, tmp_path: Path, name: str) -> None:
    dest = tmp_path / "nist"
    dest.mkdir()
    target = tmp_path / "target"
    target.write_text("keep", encoding="utf-8")
    (dest / name).symlink_to(target)
    assert refresh.main(["--dest", str(dest)]) == 1
    assert target.read_text(encoding="utf-8") == "keep"
    assert web.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/usnistgov/oscal-content/main/x.json",
        "https://example.com/x.json",
        "https://raw.githubusercontent.com.evil.example/x.json",
        "https://raw.githubusercontent.com:8443/x.json",
        "file:///etc/passwd",
    ],
)
def test_source_url_off_https_github_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], url: str
) -> None:
    assert refresh.main(["--source-url", url, "--dest", str(tmp_path / "nist")]) == 1
    assert "Next: pass an https GitHub URL to --source-url." in capsys.readouterr().err
    assert web.requests == []


@pytest.mark.parametrize("argv", [["--dest"], ["--des", "x"], ["--bogus"]])
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


UPPER_SOURCE = refresh.DEFAULT_SOURCE.replace(
    "https://raw.githubusercontent.com", "HTTPS://RAW.GITHUBUSERCONTENT.COM"
)


def test_incomplete_catalog_body_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (200, http.client.IncompleteRead(b"", 100), {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("download failed: IncompleteRead")
    assert "Next: check your network and the source URL" in err
    assert _files(dest) == []


def test_bad_status_line_on_the_catalog_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = http.client.BadStatusLine("garbage")
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    assert "download failed: garbage. Next:" in capsys.readouterr().err
    assert _files(dest) == []


@pytest.mark.parametrize(
    "route",
    [
        (200, http.client.IncompleteRead(b"[", 100), {}),
        http.client.BadStatusLine("garbage"),
    ],
    ids=["incomplete-read", "bad-status-line"],
)
def test_api_protocol_error_records_null(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], route: Any
) -> None:
    web.routes[API_URL] = route
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] is None
    assert capsys.readouterr().err.startswith(
        "notice: upstream_commit recorded as null; GitHub API unusable: "
    )


def test_unexpected_error_exits_one_with_next(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def boom(raw: bytes) -> str:
        raise ZeroDivisionError("x\x1b")

    monkeypatch.setattr(refresh, "_revision", boom)
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1
    assert capsys.readouterr().err == (
        "refresh failed: ZeroDivisionError: x?. "
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
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], url: str
) -> None:
    dest = tmp_path / "nist"
    assert refresh.main(["--source-url", url, "--dest", str(dest)]) == 1
    assert "Next: pass an https GitHub URL to --source-url." in capsys.readouterr().err
    assert not dest.exists()
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
    web.routes[refresh.DEFAULT_SOURCE] = (302, b"", {"Location": target})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    rules = "redirect to raw.githubusercontent.com breaks the URL rules."
    assert f"{rules} {refresh.RULES_NEXT}" in err
    assert "off GitHub" not in err
    assert len(web.requests) == 1
    assert _files(dest) == []


def test_api_rename_redirect_with_a_query_is_followed(web: FakeWeb, tmp_path: Path) -> None:
    moved = "https://api.github.com/repositories/1/commits?" + API_URL.split("?", 1)[1]
    web.routes[API_URL] = (301, b"", {"Location": moved})
    web.routes[moved] = (200, json.dumps([{"sha": SHA}]).encode(), {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] == SHA
    assert web.requests[-1].full_url == moved


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_unparsable_redirect_location_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str], code: int
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (code, b"", {"Location": "https://[oops/x"})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    assert "redirect Location is not a valid URL: " in err
    assert err.endswith(f"{refresh.REDIRECT_NEXT}\n")
    assert _files(dest) == []


def test_value_error_in_download_exits_one_with_next(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = ValueError("bad url")
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1
    err = capsys.readouterr().err
    assert err == "download failed: bad url. Next: check the source URL and its redirects.\n"


@pytest.mark.parametrize(("length", "code"), [(64, 0), (65, 1)])
def test_version_length_cap_is_64(web: FakeWeb, tmp_path: Path, length: int, code: int) -> None:
    body = json.dumps({"catalog": {"metadata": {"version": "v" * length}}}).encode()
    web.routes[refresh.DEFAULT_SOURCE] = (200, body, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == code
    if code == 0:
        assert _manifest(dest)["revision"] == "v" * length


def test_dest_that_is_a_file_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "nist"
    dest.write_text("x", encoding="utf-8")
    assert refresh.main(["--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    assert err == f"{dest} is not a directory. Next: pass a directory to --dest.\n"
    assert web.requests == []


def test_dest_walk_starts_at_the_first_existing_ancestor(web: FakeWeb, tmp_path: Path) -> None:
    # M5: an operator's own symlinked ancestor of --dest is followed; only new parts are created.
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    assert refresh.main(["--dest", str(tmp_path / "link" / "a" / "nist")]) == 0
    assert (real / "a" / "nist" / "catalog.json").read_bytes() == CATALOG_BYTES
    assert stat.S_IMODE((real / "a").stat().st_mode) == 0o700


def test_uppercase_scheme_and_host_record_the_upstream_commit(web: FakeWeb, tmp_path: Path) -> None:
    web.routes[UPPER_SOURCE] = (200, CATALOG_BYTES, {})
    dest = tmp_path / "nist"
    assert refresh.main(["--source-url", UPPER_SOURCE, "--dest", str(dest)]) == 0
    assert _manifest(dest)["upstream_commit"] == SHA
    assert web.requests[1].full_url == API_URL


def test_invalid_inner_version_is_not_masked_by_the_top_level_one(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = {"catalog": {"metadata": {"version": "5\n"}}, "metadata": {"version": "1.0"}}
    web.routes[refresh.DEFAULT_SOURCE] = (200, json.dumps(body).encode(), {})
    dest = tmp_path / "nist"
    assert refresh.main(["--dest", str(dest)]) == 1
    assert capsys.readouterr().err.startswith(
        "catalog.metadata.version is not a printable string of 64 characters or fewer. Next:"
    )
    assert _files(dest) == []


def test_invalid_top_level_version_names_its_key(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (200, b'{"metadata": {"version": 5}}', {})
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1
    assert capsys.readouterr().err.startswith("metadata.version is not a printable string")


def test_held_lock_exits_one_within_the_bound(
    web: FakeWeb,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(refresh, "LOCK_TIMEOUT_S", 0.2)
    dest = tmp_path / "nist"
    dest.mkdir()
    with open(dest / refresh.LOCK, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        assert refresh.main(["--dest", str(dest)]) == 1
        assert time.monotonic() - started < 5
    err = capsys.readouterr().err
    assert err.startswith("refresh lock held for 0.2 s")
    assert "Next: wait for the other refresh to finish" in err
    assert web.requests == []
    assert _files(dest) == []


def test_symlinked_lock_is_refused(web: FakeWeb, tmp_path: Path) -> None:
    dest = tmp_path / "nist"
    dest.mkdir()
    (dest / refresh.LOCK).symlink_to(tmp_path / "elsewhere.lock")
    assert refresh.main(["--dest", str(dest)]) == 1
    assert not (tmp_path / "elsewhere.lock").exists()


def test_fifo_lock_is_refused(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "nist"
    dest.mkdir()
    os.mkfifo(dest / refresh.LOCK)
    assert refresh.main(["--dest", str(dest)]) == 1
    assert "is not a regular file. Next:" in capsys.readouterr().err


def test_symlinked_frameworks_dir_is_refused(
    web: FakeWeb, plugin_data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (plugin_data / "frameworks").symlink_to(elsewhere)
    assert refresh.main([]) == 1
    assert "frameworks is a symlink. Next:" in capsys.readouterr().err
    assert list(elsewhere.iterdir()) == []
    assert web.requests == []


def test_created_parents_are_0700(web: FakeWeb, plugin_data: Path, tmp_path: Path) -> None:
    assert refresh.main([]) == 0
    for path in (plugin_data / "frameworks", plugin_data / "frameworks" / "nist"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
    deep = tmp_path / "a" / "b" / "c"
    assert refresh.main(["--dest", str(deep)]) == 0
    for path in (tmp_path / "a", tmp_path / "a" / "b", deep):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path


def test_server_reason_is_masked(
    web: FakeWeb, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    web.routes[refresh.DEFAULT_SOURCE] = (404, b"", {})
    web.reasons[refresh.DEFAULT_SOURCE] = "Not \x1b[31mFound"
    assert refresh.main(["--dest", str(tmp_path / "nist")]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "download failed: HTTP Error 404: Not ?[31mFound. Next:" in err


def test_lock_open_refuses_a_symlink_itself(tmp_path: Path) -> None:
    # M4: O_NOFOLLOW holds even when the symlink appears after the dest checks.
    (tmp_path / refresh.LOCK).symlink_to(tmp_path / "elsewhere.lock")
    with pytest.raises(refresh.RefreshError, match="is a symlink. Next:"):
        with refresh._locked(tmp_path):
            pass
    assert not (tmp_path / "elsewhere.lock").exists()


def test_created_dirs_are_0700_under_a_strict_umask(web: FakeWeb, plugin_data: Path) -> None:
    old = os.umask(0o277)
    try:
        assert refresh.main([]) == 0
    finally:
        os.umask(old)
    for path in (plugin_data / "frameworks", plugin_data / "frameworks" / "nist"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
