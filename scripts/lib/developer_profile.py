# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0252, question-path spec 6: keeps the Developer Profile (rules and tallies) in the plugin data
# folder through lib.storage, and is the one place the question path reads it. No model text.
# 0221: every list of allowed values is a fixed tuple; anything else is refused by name.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from lib import atomic, storage
from lib.operator_file import load
from lib.project_root import project_root
from lib.question_path import KINDS, OUTCOMES

FEATURE = "developer-profile"
HANDOVER = "handover.json"
RULES = "rules"
TALLIES = "tallies.json"
MAX_HANDOVER_BYTES = 8192
MAX_FILE_BYTES = 64 * 1024
MAX_RULE = 500
MIN_STREAK = 3
FINGERPRINT_LENGTH = 12
HOWS: tuple[str, ...] = ("stated", "ratified")
RULE_KEYS: tuple[str, ...] = ("kind", "rule", "how", "stated_on", "applied", "contested")
TALLY_KEYS: tuple[str, ...] = ("predicted", "hit", "miss", "streak")
RULE_HANDOVER_KEYS: tuple[str, ...] = ("kind", "rule", "how", "replaces")
TALLY_HANDOVER_KEYS: tuple[str, ...] = ("kind", "outcome", "rule")
_HEX = "0123456789abcdef"
SCRIPT = "daedalus_profile.py"
OFF_LINE = "developer-profile: off"


class Refusal(Exception):
    def __init__(self, problems: list[str], next_step: str) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems
        self.next_step = next_step


def enabled(repo_root: str | Path) -> bool:
    # 0252: fail closed; a missing, unreadable or refused personal file is false.
    try:
        return load(project_root(Path(repo_root))).developer_profile is True
    except Exception:
        return False


def _norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def fingerprint(kind: str, rule: str) -> str:
    digest = hashlib.sha256(f"{kind}\n{_norm(rule)}".encode()).hexdigest()
    return digest[:FINGERPRINT_LENGTH]


def _is_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == FINGERPRINT_LENGTH
        and all(ch in _HEX for ch in value)
    )


def _damaged(name: str, why: str) -> Refusal:
    return Refusal(
        [f"profile: {name} is damaged ({why})"],
        f"Next: read or delete {name} yourself, then rerun; the script never overwrites it.",
    )


# ---------------------------------------------------------------- files


def profile_dir() -> Path:
    return storage.data_dir(FEATURE)


def _read_json(path: Path, label: str) -> Any:
    # A link or a non-file is never read; a parse failure is a damaged file, not a traceback.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise _damaged(label, f"cannot be opened: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise _damaged(label, "not a plain file")
        raw = fh.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise _damaged(label, f"over {MAX_FILE_BYTES} bytes")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise _damaged(label, f"not valid JSON: {exc}") from None


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _check_rule(data: object, label: str) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != set(RULE_KEYS):
        raise _damaged(label, f"keys must be exactly {', '.join(RULE_KEYS)}")
    text = data["rule"]
    if data["kind"] not in KINDS:
        raise _damaged(label, f"kind {data['kind']!r} is not one of {', '.join(KINDS)}")
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_RULE or not text.isprintable():
        raise _damaged(label, f"rule must be one printable line of 1 to {MAX_RULE} characters")
    if data["how"] not in HOWS:
        raise _damaged(label, f"how {data['how']!r} is not one of {', '.join(HOWS)}")
    try:
        stamp = datetime.strptime(str(data["stated_on"]), "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        stamp = ""
    if stamp != data["stated_on"]:
        raise _damaged(label, "stated_on must be a YYYY-MM-DD date")
    if not _count(data["applied"]) or not isinstance(data["contested"], bool):
        raise _damaged(label, "applied must be a count and contested true or false")
    return data


def _rule_file_name(kind: str, fp: str) -> str:
    return f"{kind}-{fp}.json"


def load_rules() -> dict[str, dict[str, Any]]:
    # A fingerprint maps to its rule; a missing folder is no rules, anything odd is a refusal.
    folder = profile_dir() / RULES
    try:
        names = sorted(os.listdir(folder))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise Refusal(
            [f"profile: the rules folder {folder} cannot be read ({exc.strerror})"],
            "Next: fix the folder's permissions, then rerun.",
        ) from None
    out: dict[str, dict[str, Any]] = {}
    for name in names:
        kind, _, rest = name.removesuffix(".json").rpartition("-")
        if not name.endswith(".json") or kind not in KINDS or not _is_fingerprint(rest):
            raise _damaged(f"{folder / name}", "not a rule file name")
        data = _check_rule(_read_json(folder / name, str(folder / name)), str(folder / name))
        if data["kind"] != kind or fingerprint(kind, data["rule"]) != rest:
            raise _damaged(str(folder / name), "its name does not match its kind and rule")
        out[rest] = data
    return out


def load_tallies() -> dict[str, dict[str, int]]:
    path = profile_dir() / TALLIES
    if not os.path.lexists(path):
        return {}
    data = _read_json(path, str(path))
    if not isinstance(data, dict):
        raise _damaged(str(path), "must be a JSON object")
    for kind, tally in data.items():
        if kind not in KINDS:
            raise _damaged(str(path), f"kind {kind!r} is not one of {', '.join(KINDS)}")
        if (
            not isinstance(tally, dict)
            or set(tally) != set(TALLY_KEYS)
            or not all(_count(tally[key]) for key in TALLY_KEYS)
        ):
            raise _damaged(str(path), f"{kind} must hold exactly {', '.join(TALLY_KEYS)} as counts")
    return data


def streak(tallies: dict[str, dict[str, int]], kind: str) -> int:
    return tallies.get(kind, {}).get("streak", 0)


def unusable_reason(rule: dict[str, Any], tallies: dict[str, dict[str, int]]) -> str | None:
    # 0252: stated is usable at once; ratified needs the kind's streak; contested never.
    fp = fingerprint(rule["kind"], rule["rule"])
    if rule["contested"]:
        return f"rule {fp} is contested and must be restated first"
    have = streak(tallies, rule["kind"])
    if rule["how"] == "ratified" and have < MIN_STREAK:
        return f"rule {fp} is not usable yet: kind {rule['kind']} streak is {have} of {MIN_STREAK}"
    return None


def is_usable(rule: dict[str, Any], tallies: dict[str, dict[str, int]]) -> bool:
    return unusable_reason(rule, tallies) is None


def source_problem(repo_root: str | Path, kind: str, fp: str) -> str | None:
    # The question path's one read: None when the fingerprint names a usable rule of this kind.
    if not enabled(repo_root):
        return "the Developer Profile is off"
    try:
        rules = load_rules()
        tallies = load_tallies()
    except Refusal as refusal:
        return f"the Developer Profile cannot be read ({'; '.join(refusal.problems)})"
    except (OSError, RuntimeError, ValueError) as exc:
        return f"the Developer Profile cannot be read ({exc})"
    rule = rules.get(fp)
    if rule is None:
        return f"{fp!r} is not a rule in the Developer Profile"
    if rule["kind"] != kind:
        return f"rule {fp} is of kind {rule['kind']}, not {kind}"
    return unusable_reason(rule, tallies)


def _make_rules_dir() -> Path:
    base = storage.make_data_dir(FEATURE)
    folder = base / RULES
    atomic.refuse_links(folder)
    if not folder.exists():
        os.mkdir(folder, 0o700)
        os.chmod(folder, 0o700)
    return folder


def _dump(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _save_rule(folder: Path, fp: str, data: dict[str, Any]) -> None:
    atomic.write_atomic(folder / _rule_file_name(data["kind"], fp), _dump(data), 0o600)


def _save_tallies(tallies: dict[str, dict[str, int]]) -> None:
    atomic.write_atomic(profile_dir() / TALLIES, _dump(tallies), 0o600)


# ---------------------------------------------------------------- hand-over


def _handover_path(repo: str) -> Path:
    return storage.tmp_dir(FEATURE, repo) / HANDOVER


def _take_handover(repo: str) -> Any:
    # Read once, then delete whatever the outcome; a link or a non-file is never read.
    path = _handover_path(repo)
    try:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise Refusal(
                ["profile: there is no handover file"],
                f"Next: write the handover JSON to {path}, then rerun.",
            ) from None
        except OSError:
            raise Refusal(
                ["profile: the handover file is a link or cannot be read"],
                "Next: delete it, write it again, then rerun.",
            ) from None
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise Refusal(
                    ["profile: the handover is not a plain file"],
                    "Next: delete that file, then write the handover again.",
                )
            raw = fh.read(MAX_HANDOVER_BYTES + 1)
        if len(raw) > MAX_HANDOVER_BYTES:
            raise Refusal(
                [f"profile: the handover is over {MAX_HANDOVER_BYTES} bytes"],
                "Next: shorten the rule, then rerun.",
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise Refusal(
                [f"profile: the handover is not valid JSON ({exc})"],
                "Next: write valid JSON, then rerun.",
            ) from None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _keys_problem(data: object, keys: tuple[str, ...]) -> list[str]:
    if not isinstance(data, dict):
        return ["profile: the handover must be a JSON object"]
    out = [f"profile: the handover lacks {key}" for key in keys if key not in data]
    out += [f"profile: the handover has unexpected {key}" for key in data if key not in keys]
    return out


def _kind_problem(value: object) -> list[str]:
    if value not in KINDS:
        return [f"profile: kind {value!r} is not one of {', '.join(KINDS)}"]
    return []


def _rule_problems(data: object) -> list[str]:
    problems = _keys_problem(data, RULE_HANDOVER_KEYS)
    if problems:
        return problems
    assert isinstance(data, dict)
    problems = _kind_problem(data["kind"])
    text = data["rule"]
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_RULE:
        problems.append(f"profile: rule must be 1 to {MAX_RULE} characters")
    elif not text.isprintable() or not text.strip():
        problems.append("profile: rule must be one printable line with no control characters")
    if data["how"] not in HOWS:
        problems.append(f"profile: how {data['how']!r} is not one of {', '.join(HOWS)}")
    old = data["replaces"]
    if old is not None and not _is_fingerprint(old):
        problems.append(f"profile: replaces {old!r} is not null or {FINGERPRINT_LENGTH} hex")
    return problems


def _tally_problems(data: object) -> list[str]:
    problems = _keys_problem(data, TALLY_HANDOVER_KEYS)
    if problems:
        return problems
    assert isinstance(data, dict)
    problems = _kind_problem(data["kind"])
    if data["outcome"] not in OUTCOMES:
        problems.append(f"profile: outcome {data['outcome']!r} is not one of {', '.join(OUTCOMES)}")
    if data["rule"] is not None and not _is_fingerprint(data["rule"]):
        problems.append(f"profile: rule {data['rule']!r} is not null or {FINGERPRINT_LENGTH} hex")
    return problems


# ---------------------------------------------------------------- commands


def _cmd_status(repo: str, args: argparse.Namespace) -> list[str]:
    rules = load_rules()
    contested = sum(1 for r in rules.values() if r["contested"])
    storage.make_tmp_dir(FEATURE, repo)
    path = _handover_path(repo)
    return [f"developer-profile: on rules={len(rules)} contested={contested} handover={path}"]


def _cmd_rule(repo: str, args: argparse.Namespace) -> list[str]:
    storage.make_tmp_dir(FEATURE, repo)
    data = _take_handover(repo)
    problems = _rule_problems(data)
    if problems:
        raise Refusal(problems, "Next: correct the handover, write it again, then rerun.")
    kind, text, old = data["kind"], data["rule"], data["replaces"]
    fp = fingerprint(kind, text)
    rules = load_rules()
    load_tallies()
    if old is not None and (old not in rules or rules[old]["kind"] != kind):
        raise Refusal(
            [f"profile: replaces {old} is not an existing rule of kind {kind}"],
            f"Next: run `{SCRIPT} list --repo {repo} --kind {kind}` to read the fingerprints.",
        )
    if fp in rules and old is None:
        return [f"rule unchanged {fp} kind={kind}"]
    folder = _make_rules_dir()
    if fp not in rules or old == fp:
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        fresh = dict(zip(RULE_KEYS, (kind, text, data["how"], stamp, 0, False), strict=True))
        _save_rule(folder, fp, fresh)
    if old is not None and old != fp:
        os.unlink(folder / _rule_file_name(kind, old))
    return [f"rule saved {fp} kind={kind}"]


def _cmd_tally(repo: str, args: argparse.Namespace) -> list[str]:
    storage.make_tmp_dir(FEATURE, repo)
    data = _take_handover(repo)
    problems = _tally_problems(data)
    if problems:
        raise Refusal(problems, "Next: correct the handover, write it again, then rerun.")
    kind, outcome, named = data["kind"], data["outcome"], data["rule"]
    rules = load_rules()
    tallies = load_tallies()
    if named is not None and (named not in rules or rules[named]["kind"] != kind):
        raise Refusal(
            [f"profile: rule {named} is not an existing rule of kind {kind}"],
            f"Next: run `{SCRIPT} list --repo {repo} --kind {kind}` to read the fingerprints.",
        )
    tally = tallies.setdefault(kind, dict.fromkeys(TALLY_KEYS, 0))
    tally["predicted"] += 1
    if outcome == "hit":
        tally["hit"] += 1
        tally["streak"] += 1
    else:
        tally["miss"] += 1
        tally["streak"] = 0
    storage.make_data_dir(FEATURE)
    _save_tallies(tallies)
    if named is not None:
        rule = rules[named]
        if outcome == "hit":
            rule["applied"] += 1
        else:
            rule["contested"] = True
        _save_rule(_make_rules_dir(), named, rule)
    return [f"tally kind={kind} outcome={outcome} streak={tally['streak']}"]


def _cmd_list(repo: str, args: argparse.Namespace) -> list[str]:
    if args.kind is not None and args.kind not in KINDS:
        raise Refusal(
            [f"profile: kind {args.kind!r} is not one of {', '.join(KINDS)}"],
            "Next: pass one of those kinds.",
        )
    rules = load_rules()
    tallies = load_tallies()
    lines = [
        f"{fp} kind={r['kind']} usable={'yes' if is_usable(r, tallies) else 'no'} "
        f"contested={'yes' if r['contested'] else 'no'} applied={r['applied']}: {r['rule']}"
        for fp, r in sorted(rules.items(), key=lambda item: (item[1]["kind"], item[0]))
        if args.kind in (None, r["kind"])
    ]
    return lines or ["developer-profile: on, no rules saved"]


def _cmd_forget(repo: str, args: argparse.Namespace) -> list[str]:
    fp = args.fingerprint
    if not _is_fingerprint(fp):
        raise Refusal(
            [f"profile: {fp!r} is not {FINGERPRINT_LENGTH} lowercase hex characters"],
            f"Next: copy a fingerprint from `{SCRIPT} list --repo {repo}`.",
        )
    rules = load_rules()
    if fp not in rules:
        raise Refusal(
            [f"profile: no rule {fp}"],
            f"Next: run `{SCRIPT} list --repo {repo}` to read the fingerprints.",
        )
    os.unlink(profile_dir() / RULES / _rule_file_name(rules[fp]["kind"], fp))
    return [f"rule forgotten {fp}"]


COMMANDS = {
    "status": _cmd_status,
    "rule": _cmd_rule,
    "tally": _cmd_tally,
    "list": _cmd_list,
    "forget": _cmd_forget,
}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise Refusal(
            [f"profile: {message}"],
            f"Next: run `{SCRIPT} --help` to read the commands and their flags.",
        )


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=SCRIPT)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        one = sub.add_parser(name)
        one.add_argument("--repo", required=True)
        if name == "list":
            one.add_argument("--kind")
        if name == "forget":
            one.add_argument("--fingerprint", required=True)
    return parser


def _drop_handover(repo: str) -> None:
    # With the mode off a leftover handover is deleted; no folder is made and a bad path is left.
    if storage.check_tmp_dirs(FEATURE, repo) is not None:
        return
    try:
        os.unlink(_handover_path(repo))
    except OSError:
        pass


def run(argv: list[str]) -> list[str]:
    args = _parser().parse_args(argv)
    if not enabled(args.repo):
        _drop_handover(args.repo)
        return [OFF_LINE]
    return COMMANDS[args.command](args.repo, args)


def main(argv: list[str] | None = None) -> int:
    import sys

    try:
        lines = run(sys.argv[1:] if argv is None else argv)
    except Refusal as refusal:
        print("\n".join([*refusal.problems, refusal.next_step]))
        return 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"profile: {exc}\nNext: fix that, then rerun the command.")
        return 1
    print("\n".join(lines))
    return 0
