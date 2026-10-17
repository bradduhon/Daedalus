# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fetch hardening shared by the framework refresh adapters (0026).

URL rules, the GitHub-only redirect handler, the size cap, the cache lock and the
symlink-refusing destination walk. Network and file state only; no adapter knowledge.
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from pathlib import Path
from typing import IO, Any

from lib.locks import bounded_flock

ALLOWED_HOSTS = frozenset({"github.com", "raw.githubusercontent.com", "api.github.com"})
TIMEOUT_S = 60
LOCK_TIMEOUT_S = 60.0
MAX_BYTES = 64 * 1024 * 1024
CHUNK = 1024 * 1024
LOCK = ".refresh.lock"
USER_AGENT = "daedalus-refresh"
_URL_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_ENCODED_SLASH = re.compile(r"%(?:2f|5c)", re.I)
QUERY_HOST = "api.github.com"
REDIRECT_NEXT = "Next: check the source URL; redirects off GitHub are refused."
RULES_NEXT = (
    "Next: check the source URL; a redirect must stay https on GitHub with no user, "
    "fragment, dot segment, backslash or encoded slash."
)
NOT_SOURCE_NEXT = "Next: check the source URL points at the framework file."
_HTTP_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError)


class RefreshError(Exception):
    pass


def _safe(text: object) -> str:
    # M6: server-derived text reaches the terminal; mask control characters.
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _allowed(url: str, redirect: bool = False) -> bool:
    # M1: https on a GitHub host only, with no userinfo, fragment, dot segment or encoded slash.
    if not url.isascii() or _URL_BAD_CHARS.search(url) or "@" in url or "#" in url:
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    # R1-m2: GitHub's API rename redirect carries the query; nothing else may.
    if "?" in url and not (redirect and parts.hostname == QUERY_HOST):
        return False
    segments = [urllib.parse.unquote(s) for s in parts.path.split("/")]
    return (
        parts.scheme.lower() == "https"
        and parts.hostname in ALLOWED_HOSTS
        and port in (None, 443)
        and not _ENCODED_SLASH.search(parts.path)
        and not any(s in (".", "..") for s in segments)
    )


class _GitHubOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _allowed(newurl, redirect=True):
            host = urllib.parse.urlsplit(newurl).hostname
            if host in ALLOWED_HOSTS:
                raise RefreshError(f"redirect to {host} breaks the URL rules. {RULES_NEXT}")
            raise RefreshError(f"redirect to {_safe(host or newurl)} refused. {REDIRECT_NEXT}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(
        self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str, headers: Message
    ) -> Any:
        # R1-m4: urllib parses Location before redirect_request; a bad one raises ValueError.
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except ValueError as exc:
            raise RefreshError(
                f"redirect Location is not a valid URL: {_safe(exc)}. {REDIRECT_NEXT}"
            ) from exc

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _open(url: str, accept: str) -> Any:
    # 8.8: opener, not urlopen; the global opener would follow redirects to any host.
    opener = urllib.request.build_opener(_GitHubOnlyRedirect)
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    return opener.open(req, timeout=TIMEOUT_S)


def _too_big() -> RefreshError:
    return RefreshError(f"response exceeds {MAX_BYTES // (1024 * 1024)} MiB. {NOT_SOURCE_NEXT}")


def _download(url: str, out: IO[bytes]) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with _open(url, "application/json") as resp:
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise _too_big()
                digest.update(chunk)
                out.write(chunk)
    except _HTTP_ERRORS as exc:
        raise RefreshError(
            f"download failed: {_safe(exc)}. Next: check your network and the source URL, "
            "then run the script again."
        ) from exc
    except ValueError as exc:
        raise RefreshError(
            f"download failed: {_safe(exc)}. Next: check the source URL and its redirects."
        ) from exc
    return digest.hexdigest()


def _first_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if os.path.lexists(candidate):
            return candidate
    return Path(path.anchor)


def _symlink_error(path: Path) -> RefreshError:
    return RefreshError(
        f"{path} is a symlink. Next: remove the symlink; the cache must be a real path."
    )


def _check_dir(path: Path) -> None:
    mode = os.lstat(path).st_mode
    if stat.S_ISLNK(mode):
        raise _symlink_error(path)
    if not stat.S_ISDIR(mode):
        raise RefreshError(
            f"{path} is not a directory. Next: move it aside; the cache needs a directory there."
        )


def _prepare_dest(root: Path, dest: Path, names: tuple[str, ...]) -> None:
    # M5: lstat every component below the first existing ancestor; create each one 0700.
    start = _first_existing(root)
    if start == dest:
        _check_dir(dest)
    current = start
    for part in dest.relative_to(start).parts:
        current = current / part
        if os.path.lexists(current):
            _check_dir(current)
        else:
            os.mkdir(current, 0o700)
            os.chmod(current, 0o700)
    for name in (*names, LOCK):
        path = dest / name
        if os.path.lexists(path) and stat.S_ISLNK(os.lstat(path).st_mode):
            raise _symlink_error(path)


def _open_lock(path: str, _flags: int) -> int:
    # M4: O_NOFOLLOW and O_NONBLOCK so a planted symlink or FIFO cannot stand in for the lock.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise RefreshError(f"lock {path} is not a regular file. Next: remove it and retry.")
    return fd


@contextmanager
def _locked(dest: Path) -> Iterator[None]:
    try:
        fh = open(dest / LOCK, "r+", opener=_open_lock)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RefreshError(
                f"{dest / LOCK} is a symlink. Next: remove the symlink and retry."
            ) from exc
        raise
    with fh:
        try:
            bounded_flock(fh, LOCK_TIMEOUT_S, label="refresh lock")
        except RuntimeError as exc:
            held = str(exc).split(" Next:")[0]
            raise RefreshError(
                f"{held} Next: wait for the other refresh to finish, then run the script again; "
                "do not delete the .lock file."
            ) from exc
        yield


def _temp(dest: Path, prefix: str) -> IO[bytes]:
    return tempfile.NamedTemporaryFile(dir=dest, prefix=prefix, suffix=".tmp", delete=False)
