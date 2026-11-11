# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# A2, 0252: the finding store behind start, save and show; the layout and the flag come from
# lib.self_assessment; nothing is written in a project (0221: field checks are allow lists).
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lib import atomic, self_assessment, storage
from lib.project_root import project_root

ROOT = Path(__file__).resolve().parents[2]
KEYS = ("kind", "skill", "step", "text_said", "happened", "model_did", "result_changed")
TEXT_FIELDS = ("step", "text_said", "happened", "model_did")
KINDS = ("bug", "feature")
CHANGED = ("yes", "no")
MAX_TEXT = 500
KEEP_DAYS = 30
STAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
FINDING_NAME = re.compile(r"([0-9]{8}T[0-9]{6}Z)-[0-9a-f]{12}\.json")
FRONT_NAME = re.compile(r"name:[ \t]*(\S+)[ \t]*")
OFF = "self-assessment: off"


def utc_stamp(moment: datetime | None = None) -> str:
    return (moment or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")


def _skill_files() -> dict[str, Path]:
    # 0221: the skill allow list maps each name: value of a shipped SKILL.md to its file.
    found: dict[str, Path] = {}
    for path in sorted((ROOT / "skills").rglob("SKILL.md")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines[1:20] if lines[:1] == ["---"] else []:
            if line == "---":
                break
            hit = FRONT_NAME.fullmatch(line)
            if hit:
                found[hit.group(1)] = path
                break
    return found


def plugin_version() -> str:
    data = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    version = data.get("version") if isinstance(data, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError("plugin.json holds no version")
    return version


def fingerprint(kind: str, skill: str, step: str, text_said: str) -> str:
    joined = "\n".join((kind, skill, step, text_said))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]


def _project_paths(repo: str) -> set[str]:
    # The absolute forms of --repo a finding must not hold: as given, resolved, project root.
    given = Path(repo)
    paths = {os.path.abspath(given), str(given.resolve())}
    paths.add(str(project_root(given).resolve()) if given.exists() else str(given.resolve()))
    return {p for p in paths if p not in ("", "/")}


def check_text(value: object, paths: set[str]) -> str | None:
    if not isinstance(value, str):
        return "must be text"
    if not value.strip():
        return "is empty"
    if value.splitlines() != [value]:
        return "holds a line break"
    if len(value) > MAX_TEXT:
        return f"runs over {MAX_TEXT} characters"
    if any(p in value for p in paths):
        return "holds the project's absolute path"
    return None


def check_fields(obj: dict[str, object], repo: str) -> list[str]:
    # 0221: admit known shapes per field and refuse the rest; one line per broken field.
    names = _skill_files()
    paths = _project_paths(repo)
    out = [f"refused: {k}: missing" for k in KEYS if k not in obj]
    out += [f"refused: {k}: not allowed" for k in sorted(obj) if k not in KEYS]
    if out:
        return out
    if obj["kind"] not in KINDS:
        out.append("refused: kind: must be bug or feature")
    if not isinstance(obj["skill"], str) or obj["skill"] not in names:
        out.append("refused: skill: is not the name of a shipped skill")
    if obj["result_changed"] not in CHANGED:
        out.append("refused: result_changed: must be yes or no")
    for key in TEXT_FIELDS:
        reason = check_text(obj[key], paths)
        if reason:
            out.append(f"refused: {key}: {reason}")
    return out


def read_json(path: Path) -> tuple[dict[str, object] | None, str | None]:
    # No file, a symlink, an oversize file or bad JSON each give one reason, never a traceback.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None, "no file"
    except OSError:
        return None, "cannot be read (a symlink or unreadable file)"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "is not a regular file"
        if info.st_size > self_assessment.MAX_HANDOVER_BYTES:
            return None, f"is over {self_assessment.MAX_HANDOVER_BYTES} bytes"
        raw = os.read(fd, self_assessment.MAX_HANDOVER_BYTES + 1)
    except OSError:
        return None, "cannot be read"
    finally:
        os.close(fd)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "is not valid JSON"
    if not isinstance(obj, dict):
        return None, "is not a JSON object"
    return obj, None


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def start(repo: str) -> tuple[int, list[str]]:
    if not self_assessment.enabled(repo):
        return 0, [OFF]
    stamp = utc_stamp()
    try:
        folder = self_assessment.make_handover_dir(repo)
    except (OSError, RuntimeError) as exc:
        return 1, [f"self-assessment: refused: {exc}"]
    target = folder / self_assessment.handover_name(stamp)
    return 0, [f"self-assessment: on since={stamp} handover={target}"]


def _findings_folder(make: bool) -> Path:
    folder = self_assessment.findings_dir()
    if not make:
        return folder
    top = storage.make_data_dir(self_assessment.FEATURE)
    for part in (top, folder):
        atomic.refuse_links(part)
        if not part.exists():
            os.mkdir(part, 0o700)
            os.chmod(part, 0o700)
    return folder


def _store(obj: dict[str, object]) -> tuple[int, list[str]]:
    try:
        version = plugin_version()
        skill_bytes = _skill_files()[str(obj["skill"])].read_bytes()
        folder = _findings_folder(make=True)
    except (OSError, RuntimeError, ValueError) as exc:
        return 1, [f"refused: findings: {exc}"]
    fp = fingerprint(str(obj["kind"]), str(obj["skill"]), str(obj["step"]), str(obj["text_said"]))
    record = {k: obj[k] for k in KEYS}
    record.update(
        fingerprint=fp,
        plugin_version=version,
        skill_hash=hashlib.sha256(skill_bytes).hexdigest()[:12],
    )
    file_name = f"{utc_stamp()}-{fp}.json"
    try:
        atomic.write_atomic(folder / file_name, json.dumps(record, indent=2) + "\n", 0o600)
    except OSError as exc:
        return 1, [f"refused: findings: {exc}"]
    return 0, [f"saved: {file_name} fingerprint={fp}"]


def save(repo: str, since: str) -> tuple[int, list[str]]:
    try:
        name = self_assessment.handover_name(since)
    except ValueError:
        return 1, ["refused: hand-over: the stamp is not YYYYMMDDTHHMMSSZ"]
    reason = self_assessment.check_dirs(repo)
    if reason is not None:
        # A folder that fails the check is never entered, so nothing in it is deleted either.
        return 1, [f"refused: hand-over: {reason}"]
    target = self_assessment.handover_dir(repo) / name
    try:
        if not self_assessment.enabled(repo):
            return 0, ["self-assessment: off; nothing saved"]
        obj, why = read_json(target)
        if obj is None:
            return 1, [f"refused: hand-over: {why}"]
        problems = check_fields(obj, repo)
        return (1, problems) if problems else _store(obj)
    finally:
        _unlink(target)


def _clean_handover(repo: str) -> None:
    if self_assessment.check_dirs(repo) is not None:
        return
    try:
        entries = list(self_assessment.handover_dir(repo).iterdir())
    except OSError:
        return
    for entry in entries:
        if self_assessment.HANDOVER_NAME.fullmatch(entry.name):
            _unlink(entry)


def show(repo: str, since: str) -> tuple[int, list[str]]:
    if not self_assessment.enabled(repo):
        return 0, [OFF]
    if not STAMP.fullmatch(since):
        return 1, ["refused: since: the stamp is not YYYYMMDDTHHMMSSZ"]
    _clean_handover(repo)
    try:
        folder = _findings_folder(make=False)
    except RuntimeError as exc:
        return 1, [f"refused: findings: {exc}"]
    cutoff = utc_stamp(datetime.now(UTC) - timedelta(days=KEEP_DAYS))
    shown: dict[str, list[str]] = {"bug": [], "feature": []}
    try:
        entries = sorted(folder.iterdir()) if folder.is_dir() and not folder.is_symlink() else []
    except OSError:
        entries = []
    for entry in entries:
        hit = FINDING_NAME.fullmatch(entry.name)
        if not hit:
            continue
        if hit.group(1) < cutoff:
            _unlink(entry)
        elif hit.group(1) >= since:
            obj, why = read_json(entry)
            if obj is not None and set(KEYS) <= set(obj) and obj["kind"] in KINDS:
                shown[str(obj["kind"])].append(f"{obj['skill']}: {obj['step']}: {obj['happened']}")
    out = [f"Bugs ({len(shown['bug'])})", *shown["bug"]]
    out += [f"Features ({len(shown['feature'])})", *shown["feature"]]
    return 0, out
