# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0265: the run validates a unit's Terraform outside the kernel wrapper, on a staged copy of the
# unit tip's .tf files read as git blobs, with providers from the run's mirror alone. Modules are
# never downloaded: a local module is staged and listed in a module manifest written here, and
# any other source leaves its root not validated. Diagnostics print summaries only, never detail.
from __future__ import annotations

import json
import os
import posixpath
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from lib import hcl_reader, provider_mirror, storage, train_state

FEATURE = "terraform-validate"
STATE_KEY = "validate"
TIMEOUT_S = 300
TREE, DATA, HOME, RC = "tree", "data", "home", "terraformrc"
# 0265: -get=false keeps every module getter (git, hg, http) from running; no -lockfile mode,
# because the staged lock is a hash-free copy written here and init may rewrite it.
INIT_ARGS = ("init", "-backend=false", "-input=false", "-get=false", "-no-color", "-json")
VALIDATE_ARGS = ("validate", "-no-color", "-json")
MAX_ROOTS, MAX_FOLDERS, MAX_FILES, MAX_DEPTH = 32, 64, 256, 16
NAME_MAX, PATH_MAX = 255, 4096
DIAG_SHOWN, SUMMARY_MAX = 5, 160
LOCAL_PREFIXES = ("./", "../")
OVERRIDE = "override.tf"
TYPED_BLOCKS = frozenset({"resource", "data", "ephemeral"})
BUILTIN = "terraform"
DEFAULT_HOST = "registry.terraform.io"
# 0265: the one init summary that means a provider version is missing from the mirror.
MISSING_SUMMARY = "Failed to query available provider packages"
CLEAN, FAILED, NOT_VALIDATED, NEEDS_PROVIDER = "clean", "failed", "not validated", "needs provider"
R_VALIDATE_NO_RUN = (
    "validate: no run is marked in {root}. Next: start a run first; the build phase runs this "
    "command on a unit after its coder hands it in."
)
NEXT_RERUN = "Next: fix the cause, then run daedalus_train.py validate --repo {repo} --unit {unit}."
NO_BINARY = "no terraform outside the project is on PATH. {rerun}"
NO_MIRROR = (
    "the run has no provider mirror. Next: run daedalus_train.py providers from the main "
    "session, then run validate again."
)
NEXT_ROUTE = (
    "Next: send the failed lines above to the unit's coder as one fix round, then run validate "
    "again after its next COMPLETE line."
)
NEXT_UNSTAGED = (
    "Next: use a local module or plain .tf files if the run should check it; the verifier "
    "reads the files either way."
)
NEXT_PROVIDER = (
    "Next: ask the operator the build phase's missing-provider question; after a yes and the "
    "providers --allow call, run validate again."
)


@dataclass
class Root:
    # 0265: one root folder of the unit tip and what staging it found.
    folder: str
    folders: list[str] = field(default_factory=list)
    modules: list[dict[str, str]] = field(default_factory=list)
    providers: dict[str, str] = field(default_factory=dict)
    reason: str = ""


@dataclass
class Tip:
    # 0265: the unit tip's regular files by path, and every other entry's path.
    files: dict[str, tuple[str, int]]
    other: set[str]
    top: str


def _shown(text: str, limit: int = SUMMARY_MAX) -> str:
    return provider_mirror._printable(text)[:limit]


def _safe_path(path: str) -> bool:
    # 0265: a relative path of plain parts; no empty, dot, dot-dot or unprintable part.
    parts = path.split("/")
    return (
        0 < len(path) <= PATH_MAX
        and all(p not in ("", ".", "..") and len(p) <= NAME_MAX and p.isprintable() for p in parts)
        and not any(p in provider_mirror.SKIP_DIRS for p in parts)
    )


def _folder_of(path: str) -> str:
    return path.rpartition("/")[0]


def _join(folder: str, name: str) -> str:
    return f"{folder}/{name}" if folder else name


def _listing(tip: Tip, folder: str) -> tuple[list[tuple[str, str, int]], str]:
    # 0265: the folder's regular .tf files, or the reason the folder cannot be staged whole.
    found: list[tuple[str, str, int]] = []
    for path in sorted(set(tip.files) | tip.other):
        if _folder_of(path) != folder:
            continue
        name = path.rpartition("/")[2]
        if name.endswith(".tf.json"):
            return [], f"{_shown(path)} is a JSON Terraform file, which the run does not read"
        if not name.endswith(".tf"):
            continue
        if path in tip.other:
            return [], f"{_shown(path)} is a link or not a regular file"
        blob, size = tip.files[path]
        if size > provider_mirror.MAX_TF_BYTES:
            return [], f"{_shown(path)} is larger than {provider_mirror.MAX_TF_BYTES} bytes"
        if not _safe_path(path):
            return [], f"{_shown(path)} has a name the run does not stage"
        found.append((name, blob, size))
    if len(found) > MAX_FILES:
        return [], f"{_shown(folder) or '.'} holds more than {MAX_FILES} Terraform files"
    return found, ""


def _object_strings(source: str) -> dict[str, str] | None:
    # 0265: the string members of one `{ key = "value" }` object, read by tokens; else None.
    try:
        toks = hcl_reader.tokenize(source)
    except hcl_reader.HclError:
        return None
    text = [source[t.start : t.end] for t in toks]
    kinds = [t.kind for t in toks]
    if not toks or text[0] != "{" or text[-1] != "}":
        return None
    found: dict[str, str] = {}
    i, end = 1, len(toks) - 1
    while i < end:
        if kinds[i] == hcl_reader.NEWLINE or text[i] == ",":
            i += 1
            continue
        if kinds[i] not in (hcl_reader.IDENT, hcl_reader.STRING) or i + 1 >= end:
            return None
        if text[i + 1] not in ("=", ":"):
            return None
        key = text[i] if kinds[i] == hcl_reader.IDENT else hcl_reader.string_value(text[i])
        j, depth = i + 2, 0
        while j < end and not (depth == 0 and (kinds[j] == hcl_reader.NEWLINE or text[j] == ",")):
            if kinds[j] == hcl_reader.PUNCT and text[j] in "([{":
                depth += 1
            elif kinds[j] == hcl_reader.PUNCT and text[j] in ")]}":
                depth -= 1
            j += 1
        if j == i + 3 and kinds[i + 2] == hcl_reader.STRING:
            found[key] = hcl_reader.string_value(text[i + 2])
        i = j
    return found


def _address(source: str) -> str | None:
    # 0265: host/namespace/type in lower case from a written source; None for a builtin or bad one.
    parts = source.strip().lower().split("/")
    if len(parts) == 2:
        parts = [DEFAULT_HOST, *parts]
    if len(parts) != 3 or parts[:2] == ["terraform.io", "builtin"]:
        return None
    address = "/".join(parts)
    return address if provider_mirror.parse_allow(address) is not None else None


def _read_providers(root: Root, blocks: list[hcl_reader.Block]) -> None:
    # 0265: each local provider name to its source and constraint, as Terraform maps them.
    used: set[str] = set()
    declared: set[str] = set()
    for block in blocks:
        if block.type == "provider" and block.labels:
            used.add(block.labels[0])
        if block.type in TYPED_BLOCKS and block.labels:
            chosen = block.attributes.get("provider", "").partition(".")[0].strip()
            used.add(chosen or block.labels[0].partition("_")[0])
        if block.type != "terraform":
            continue
        for inner in (b for b in block.blocks if b.type == "required_providers"):
            for name, value in inner.attributes.items():
                declared.add(name)
                _declare(root, name, value)
    for name in sorted(used - declared - {BUILTIN}):
        if set(name) <= provider_mirror.LOCAL_NAME_CHARS:
            address = _address(f"hashicorp/{name}")
            if address is not None:
                root.providers.setdefault(address, "")


def _declare(root: Root, name: str, value: str) -> None:
    # 0265: one required_providers entry, an object or the older bare version string.
    entry = _object_strings(value)
    try:
        legacy = hcl_reader.string_value(value) if entry is None else None
    except hcl_reader.HclError:
        return
    stated = entry or {}
    address = _address(stated.get("source", f"hashicorp/{name}"))
    version = legacy if legacy is not None else stated.get("version", "")
    if address is not None:
        root.providers[address] = _shown(version, provider_mirror.CONSTRAINT_MAX)


def _module_target(folder: str, label: str, source: str, top: str) -> tuple[str, str]:
    # 0265: (repo-relative module folder, "") for a local source in the repository, else ("", why).
    shown = _shown(source)
    if not source.startswith(LOCAL_PREFIXES):
        return "", f"module {label} comes from {shown}, which the run does not download"
    target = posixpath.normpath(posixpath.join(folder or ".", source))
    if target == "..":
        return "", f"module {label} points at {shown}, which leaves the repository"
    if target.startswith("../") or os.path.isabs(target):
        return "", f"module {label} points at {shown}, which leaves the repository"
    target = "" if target == "." else target
    if target and not _safe_path(target):
        return "", f"module {label} points at {shown}, a folder the run does not stage"
    real = os.path.realpath(os.path.join(top, target))
    if real != top and not real.startswith(top + os.sep):
        return "", f"module {label} points at {shown}, which leaves the repository"
    return target, ""


def _read_folder(
    tip: Tip, root: Root, folder: str, key: str, depth: int, texts: dict[str, str]
) -> None:
    # 0265: stage one folder's .tf files, then follow each local module call it makes.
    if root.reason:
        return
    if depth > MAX_DEPTH or len(root.folders) > MAX_FOLDERS:
        root.reason = f"its module calls nest deeper or wider than {MAX_FOLDERS} folders"
        return
    listing, reason = _listing(tip, folder)
    if reason:
        root.reason = reason
        return
    if folder not in root.folders:
        root.folders.append(folder)
    calls: dict[str, str] = {}
    blocks: list[hcl_reader.Block] = []
    # 0265: override files last, so their module source wins as it does in Terraform.
    ordered = sorted(listing, key=lambda f: (f[0] == OVERRIDE or f[0].endswith("_" + OVERRIDE), f))
    for name, blob, _ in ordered:
        path = _join(folder, name)
        if path not in texts:
            text = provider_mirror._git_text(tip.top, ["cat-file", "blob", blob])
            if text is None:
                root.reason = f"{_shown(path)} could not be read as text"
                return
            texts[path] = text
        try:
            parsed = hcl_reader.parse(texts[path])
        except hcl_reader.HclError as exc:
            root.reason = f"the Terraform reader could not parse {_shown(path)} ({exc})"
            return
        blocks += parsed
        for block in parsed:
            if block.type != "module" or "source" not in block.attributes:
                continue
            label = block.labels[0] if len(block.labels) == 1 else ""
            if not label or not set(label) <= provider_mirror.LOCAL_NAME_CHARS:
                root.reason = f"a module block in {_shown(path)} has a name the run does not read"
                return
            try:
                calls[label] = hcl_reader.string_value(block.attributes["source"])
            except hcl_reader.HclError:
                root.reason = (
                    f"module {label} in {_shown(path)} has a source that is not plain text"
                )
                return
    _read_providers(root, blocks)
    for label, source in calls.items():
        target, why = _module_target(folder, label, source, tip.top)
        if why:
            root.reason = why
            return
        child = f"{key}.{label}" if key else label
        rel = posixpath.relpath(target or ".", root.folder or ".")
        root.modules.append({"Key": child, "Source": source, "Dir": rel})
        _read_folder(tip, root, target, child, depth + 1, texts)


def _lock_text(text: str) -> str:
    # 0265: the lock's provider versions and constraints only; hashes are dropped, see INIT_ARGS.
    try:
        blocks = hcl_reader.parse(text)
    except hcl_reader.HclError:
        return ""
    lines: list[str] = []
    for block in blocks:
        if block.type != "provider" or len(block.labels) != 1:
            continue
        if provider_mirror.parse_allow(block.labels[0]) is None:
            continue
        fields: list[str] = []
        for name in ("version", "constraints"):
            if name not in block.attributes:
                continue
            try:
                value = hcl_reader.string_value(block.attributes[name])
            except hcl_reader.HclError:
                break
            if not (
                0 < len(value) <= provider_mirror.CONSTRAINT_MAX
                and set(value) <= provider_mirror.CONSTRAINT_CHARS
            ):
                break
            fields.append(f'  {name} = "{value}"')
        else:
            if fields:
                lines += [f'provider "{block.labels[0]}" {{', *fields, "}", ""]
    return "\n".join(lines)


def changed_roots(top: str, base: str, tip: str, excluded: tuple[str, ...]) -> list[str] | None:
    # 0265: folders of the .tf and lock files the unit changed, base..tip; None on a git failure.
    out = provider_mirror._git_text(
        top,
        ["diff", "--name-only", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", base, tip],
    )
    if out is None:
        return None
    folders: list[str] = []
    for path in sorted(p for p in out.split("\0") if p):
        changed = path.endswith(".tf") or path.rpartition("/")[2] == provider_mirror.LOCK_FILE
        if not changed or provider_mirror._skipped(path, top, excluded):
            continue
        folder = _folder_of(path)
        if folder not in folders:
            folders.append(folder)
    return folders


def _tip_files(top: str, tip: str) -> Tip | None:
    entries = provider_mirror.tree_entries(top, tip)
    if entries is None:
        return None
    files = {path: (blob, size) for regular, path, blob, size in entries if regular}
    return Tip(files, {path for regular, path, _, _ in entries if not regular}, top)


def _write_tree(stage: Path, root: Root, tip: Tip, texts: dict[str, str]) -> None:
    # 0265: the root's and its local modules' .tf files, and a hash-free lock, all mode 0600.
    for folder in root.folders:
        target = _staged(stage, folder)
        os.makedirs(target, 0o700, exist_ok=True)
        for path, text in texts.items():
            if _folder_of(path) == folder:
                provider_mirror._write_new(target / path.rpartition("/")[2], text)
    lock_path = _join(root.folder, provider_mirror.LOCK_FILE)
    if lock_path in tip.files and tip.files[lock_path][1] <= provider_mirror.MAX_TF_BYTES:
        raw = provider_mirror._git_text(tip.top, ["cat-file", "blob", tip.files[lock_path][0]])
        lock = _lock_text(raw) if raw is not None else ""
        if lock:
            provider_mirror._write_new(
                _staged(stage, root.folder) / provider_mirror.LOCK_FILE, lock
            )


def _staged(stage: Path, folder: str) -> Path:
    return stage / TREE / folder if folder else stage / TREE


def tf_env(
    stage: Path, data: Path, source: dict[str, str], top: str
) -> tuple[dict[str, str], list[str]]:
    # 0265: fetch_env narrowed to its fixed values; no PATH, proxy, token or caller config remains.
    env, secrets = provider_mirror.fetch_env(data, source, top)
    kept = {k: v for k, v in env.items() if k in provider_mirror.FIXED_ENV}
    kept.update(
        {
            "HOME": str(stage / HOME),
            "PATH": "",
            "TF_CLI_CONFIG_FILE": str(stage / RC),
            "TF_DATA_DIR": str(data),
        }
    )
    return kept, secrets


def _clean_summary(text: str, stage: Path, secrets: list[str]) -> str:
    # 0265: untrusted text; staging prefixes cut, other absolute paths and caller values withheld.
    tree = str(stage / TREE)
    words: list[str] = []
    for word in provider_mirror._printable(text).split():
        bare = word.strip("\"'(),:;")
        if bare.startswith(tree + "/"):
            word = word.replace(tree + "/", "")
        elif bare.startswith("/") or bare.startswith("~"):
            word = provider_mirror.WITHHELD
        words.append(word)
    line = " ".join(words)
    for secret in secrets:
        line = line.replace(secret, provider_mirror.WITHHELD)
    return line[:SUMMARY_MAX] or "no summary"


def _place(diag: dict[str, object], root: str, stage: Path) -> str:
    # 0265: the repo-relative file and line of a diagnostic, or "" when it names none we staged.
    where = diag.get("range")
    if not isinstance(where, dict):
        return ""
    name, start = where.get("filename"), where.get("start")
    line = start.get("line") if isinstance(start, dict) else None
    if not isinstance(name, str) or not name:
        return ""
    tree = str(stage / TREE)
    if os.path.isabs(name):
        rel = os.path.relpath(name, tree) if name.startswith(tree + os.sep) else ".."
    else:
        rel = posixpath.normpath(posixpath.join(root or ".", name))
    shown = provider_mirror.WITHHELD if rel == ".." or rel.startswith("../") else _shown(rel)
    return f"{shown}:{line}" if isinstance(line, int) and not isinstance(line, bool) else shown


def _errors(
    payloads: list[dict[str, object]], root: str, stage: Path, secrets: list[str]
) -> list[tuple[str, str]]:
    # 0265: (raw summary, printed line) of each error diagnostic; the detail is never read.
    found: list[tuple[str, str]] = []
    for diag in payloads:
        if diag.get("severity") != "error":
            continue
        raw = diag.get("summary")
        summary = _clean_summary(raw if isinstance(raw, str) else "", stage, secrets)
        place = _place(diag, root, stage)
        found.append(
            (raw if isinstance(raw, str) else "", f"{place}: {summary}" if place else summary)
        )
    return found


def _init_diagnostics(out: str) -> list[dict[str, object]] | None:
    # 0265: the diagnostic objects of init's JSON lines; None when no line was JSON.
    found: list[dict[str, object]] = []
    seen = False
    for text in out.splitlines():
        try:
            item = json.loads(text)
        except ValueError:
            continue
        seen = True
        diag = item.get("diagnostic") if isinstance(item, dict) else None
        if isinstance(diag, dict):
            found.append(diag)
    return found if seen else None


def _validate_result(out: str) -> tuple[bool, list[dict[str, object]]] | None:
    try:
        item = json.loads(out)
    except ValueError:
        return None
    if not isinstance(item, dict) or not isinstance(item.get("valid"), bool):
        return None
    diags = item.get("diagnostics")
    listed = [d for d in diags if isinstance(d, dict)] if isinstance(diags, list) else []
    return bool(item["valid"]), listed


@dataclass
class Outcome:
    folder: str
    result: str
    lines: list[str]


def _missing(root: Root, mirror: str) -> list[str]:
    # 0265: each provider the files name whose folder the run's mirror does not hold.
    missing: list[str] = []
    for address, constraint in sorted(root.providers.items()):
        folder = os.path.join(mirror, *address.split("/"))
        if os.path.islink(folder) or not os.path.isdir(folder):
            missing.append(f"{address} (version {constraint or 'none stated'})")
    return missing


def _run_root(
    binary: str,
    stage: Path,
    root: Root,
    source: dict[str, str],
    top: str,
    timeout: float,
) -> Outcome:
    name = _shown(root.folder) or "."
    data = stage / DATA
    os.mkdir(data / "modules", 0o700)
    manifest = [{"Key": "", "Source": "", "Dir": "."}, *root.modules]
    provider_mirror._write_new(data / "modules" / "modules.json", json.dumps({"Modules": manifest}))
    env, secrets = tf_env(stage, data, source, top)
    cwd = str(_staged(stage, root.folder))
    try:
        code, out, err = provider_mirror.run_terraform(
            [binary, *INIT_ARGS], cwd, env, timeout, True
        )
    except OSError as exc:
        code, out, err = -1, "", f"Error: terraform could not start ({exc.strerror})"
    if code != 0:
        diags = _init_diagnostics(out)
        errors = _errors(diags or [], root.folder, stage, secrets)
        if any(raw == MISSING_SUMMARY for raw, _ in errors):
            named = ", ".join(
                f"{a} (version {c or 'none stated'})" for a, c in sorted(root.providers.items())
            )
            why = (
                "it needs a provider version the run's mirror lacks; the files name "
                f"{named or 'no provider by address'}"
            )
            return _skip(name, NEEDS_PROVIDER, why, NEXT_PROVIDER)
        if not errors:
            why = provider_mirror.first_error(err, secrets)
            return Outcome(
                name,
                NOT_VALIDATED,
                [
                    f"validate: {name}: not validated, because terraform init gave no readable "
                    f"result ({_clean_summary(why, stage, secrets)})."
                ],
            )
        return _failed(name, "terraform init", errors)
    try:
        code, out, err = provider_mirror.run_terraform(
            [binary, *VALIDATE_ARGS], cwd, env, timeout, True
        )
    except OSError as exc:
        code, out, err = -1, "", f"Error: terraform could not start ({exc.strerror})"
    result = _validate_result(out)
    if result is None:
        why = _clean_summary(provider_mirror.first_error(err, secrets), stage, secrets)
        return Outcome(
            name,
            NOT_VALIDATED,
            [
                f"validate: {name}: not validated, because terraform validate gave no readable "
                f"result ({why})."
            ],
        )
    valid, diags = result
    if valid:
        return Outcome(name, CLEAN, [f"validate: {name}: validated clean."])
    errors = _errors(diags, root.folder, stage, secrets) or [("", "invalid, with no error listed")]
    return _failed(name, "terraform validate", errors)


def _skip(name: str, result: str, why: str, next_line: str = "") -> Outcome:
    line = f"validate: {name}: not validated, because {why}."
    return Outcome(name, result, [f"{line} {next_line}" if next_line else line])


def _failed(name: str, step: str, errors: list[tuple[str, str]]) -> Outcome:
    lines = [f"validate: {name}: failed; {step} reported:"]
    lines += [f"validate:   {line}" for _, line in errors[:DIAG_SHOWN]]
    if len(errors) > DIAG_SHOWN:
        lines.append(f"validate:   and {len(errors) - DIAG_SHOWN} more.")
    return Outcome(name, FAILED, lines)


def make_stage(repo: str, train_id: str) -> Path:
    # 0265: a fresh 0700 folder per call under the run's own folder of this feature.
    base = storage.make_tmp_dir(FEATURE, repo)
    run = base / train_id
    if not os.path.lexists(run):
        os.mkdir(run, 0o700)
        os.chmod(run, 0o700)
    reason = provider_mirror._folder_problem(run)
    if reason is not None:
        raise RuntimeError(reason)
    return Path(tempfile.mkdtemp(prefix="unit-", dir=run))


def _root_stage(stage: Path, index: int, mirror: str) -> Path:
    # 0265: one folder per root, so roots never share staged files, a data folder or a config.
    folder = stage / str(index)
    os.mkdir(folder, 0o700)
    for name in (TREE, DATA, HOME):
        os.mkdir(folder / name, 0o700)
    provider_mirror._write_new(folder / RC, provider_mirror.cli_config(mirror))
    return folder


@dataclass
class Unit:
    # 0265: the unit as the run's state records it; nothing here comes from an argument path.
    label: str
    name: str
    branch: str


def unit_tip(top: str, branch: str) -> str:
    # 0265: the 40-hex commit the unit branch names, or "" when git cannot name one.
    if not branch or branch.startswith("-"):
        return ""
    out = provider_mirror._git_text(
        top,
        ["rev-parse", "--verify", "--quiet", "--end-of-options", f"refs/heads/{branch}^{{commit}}"],
    )
    value = (out or "").strip()
    return value if provider_mirror._hex(value, 40) else ""


def validate(
    repo: str,
    train_id: str,
    unit: Unit,
    excluded: tuple[str, ...],
    source: dict[str, str],
    timeout: float | None = None,
) -> tuple[list[str], list[Outcome]]:
    # 0265: one plain line per root; never runs in or reads from the unit worktree on disk.
    top = provider_mirror._resolved(repo)
    rerun = NEXT_RERUN.format(repo=top, unit=unit.label)
    base = provider_mirror._base(top, train_id)
    tip = unit_tip(top, unit.branch)
    if not base or not tip:
        return [
            f"warning: validate: the run's base or the unit's branch could not be read. {rerun}"
        ], []
    folders = changed_roots(top, base, tip, excluded)
    files = _tip_files(top, tip) if folders is not None else None
    if folders is None or files is None:
        return [f"warning: validate: git could not list the unit's changes. {rerun}"], []
    # 0265: a folder whose .tf files the unit deleted, all of them, is no root.
    roots = [f for f in folders if any(_listing(files, f))]
    if not roots:
        lines = ["validate: the unit changes no Terraform file, so nothing was validated."]
        _record(top, train_id, unit, tip, [], lines)
        return lines, []
    grant = provider_mirror.granted_mirror(top)
    binary = provider_mirror.terraform_path(top, source.get("PATH", ""))
    if binary is None or not grant.path:
        why = NO_BINARY.format(rerun=rerun) if binary is None else grant.reason
        lines = [f"warning: validate: nothing was validated, because {why or NO_MIRROR}"]
        _record(top, train_id, unit, tip, [], lines)
        return lines, []
    outcomes = _stage_and_run(top, train_id, roots, files, grant.path, binary, source, timeout)
    lines = [line for o in outcomes for line in o.lines]
    if any(o.result == FAILED for o in outcomes):
        lines.append(NEXT_ROUTE)
    _record(top, train_id, unit, tip, outcomes, lines)
    return lines, outcomes


def _stage_and_run(
    top: str,
    train_id: str,
    roots: list[str],
    tip: Tip,
    mirror: str,
    binary: str,
    source: dict[str, str],
    timeout: float | None,
) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for folder in roots[MAX_ROOTS:]:
        name = _shown(folder) or "."
        outcomes.append(
            Outcome(
                name,
                NOT_VALIDATED,
                [
                    f"validate: {name}: not validated, because the unit changes more than "
                    f"{MAX_ROOTS} Terraform folders."
                ],
            )
        )
    try:
        stage = make_stage(top, train_id)
    except (OSError, RuntimeError) as exc:
        return [
            Outcome(
                ".",
                NOT_VALIDATED,
                [f"warning: validate: the staging folder could not be made ({_shown(str(exc))})."],
            ),
            *outcomes,
        ]
    try:
        for index, folder in enumerate(roots[:MAX_ROOTS]):
            outcomes.insert(
                index, _one_root(top, stage, index, folder, tip, mirror, binary, source, timeout)
            )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return outcomes


def _one_root(
    top: str,
    stage: Path,
    index: int,
    folder: str,
    tip: Tip,
    mirror: str,
    binary: str,
    source: dict[str, str],
    timeout: float | None,
) -> Outcome:
    name = _shown(folder) or "."
    root = Root(folder)
    texts: dict[str, str] = {}
    if folder and not _safe_path(folder):
        root.reason = "its folder name is one the run does not stage"
    _read_folder(tip, root, folder, "", 0, texts)
    if root.reason:
        return _skip(name, NOT_VALIDATED, root.reason, NEXT_UNSTAGED)
    missing = _missing(root, mirror)
    if missing:
        why = f"it needs the provider {', '.join(missing)}, which the run's mirror lacks"
        return _skip(name, NEEDS_PROVIDER, why, NEXT_PROVIDER)
    try:
        own = _root_stage(stage, index, mirror)
        _write_tree(own, root, tip, texts)
    except OSError as exc:
        return _skip(name, NOT_VALIDATED, f"its files could not be staged ({exc.strerror})")
    return _run_root(binary, own, root, source, top, TIMEOUT_S if timeout is None else timeout)


def _record(
    top: str, train_id: str, unit: Unit, tip: str, outcomes: list[Outcome], lines: list[str]
) -> None:
    # 0265: per root its result and printed lines, with the unit tip they judged.
    record = {
        "tip": tip,
        "roots": [{"folder": o.folder, "result": o.result, "lines": o.lines} for o in outcomes],
    }

    def edit(state: dict[str, object]) -> None:
        raw = state.get("units")
        for item in raw if isinstance(raw, list) else []:
            if isinstance(item, dict) and item.get("name") == unit.name:
                item[STATE_KEY] = record

    try:
        train_state.change(Path(top), train_id, edit)
    except train_state.TrainStateError as exc:
        lines.append(f"warning: validate: the run state was not updated ({exc})")
