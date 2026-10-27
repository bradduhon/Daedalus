#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0135, 0136, D.7: freezes a document train's sources into .claude/daedalus/trains/<id>.sources.json
# and verifies them; checks/doc_outputs.py reads the same file through load_manifest.
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic, jail  # noqa: E402
from lib.audit import DataDirError, check_project_data_dir  # noqa: E402
from lib.config import (  # noqa: E402
    ConfigError,
    ExcludedRoot,
    load_config,
    resolve_excluded_roots,
    root_ignored,
)
from lib.project_root import in_git_work_tree, project_root  # noqa: E402
from lib.shell import _under  # noqa: E402

# 22: the --help text, kept below the future import as a plain string.
DESCRIPTION = (
    "Freeze the sources of a document train (Addendum D.7). Each --source is "
    "<alias>=<role>:<path>[:<topic>,...]; roles are baseline, amendment, style, correspondence "
    "and reference. Writes .claude/daedalus/trains/<train>.sources.json (0600) with each "
    "source's sha256 and line count and the excluded roots the project config resolves, then "
    "prints it. Exit 1: a source is missing, not a regular file, or a working file by "
    "--working-glob, or the output folder is the project root, outside the project, or is or "
    "holds a protected path. Exit 2: two baselines without --baselines-only, a style source "
    "with topics, or a malformed source. Exit 3: an excluded path root git does not ignore, "
    "or bad project metadata. --verify <manifest> recomputes every hash and exits 4 on a "
    "mismatch, exits 1 when the recorded output folder fails the same output folder check, "
    "then lints the outputs for en and em dashes, placeholder copy and style-source "
    "sentences carrying a number, and exits 5 on any finding."
)
ROLES = ("baseline", "amendment", "style", "correspondence", "reference")
EXIT_PATH, EXIT_SHAPE, EXIT_ROOT, EXIT_MISMATCH, EXIT_LINT = 1, 2, 3, 4, 5
TRAINS_DIR = "trains"
SUFFIX = ".sources.json"
_TRAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")
_TOPICS = re.compile(r"[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*")
R_OUTPUT_ROOT = (
    "output folder {out} is the project root, so a document agent could write every project "
    "file (D.5). Next: name a folder below the project root, such as one under an excluded root."
)
R_OUTPUT_OUTSIDE = (
    "output folder {out} is outside the project {repo}, so a document agent could write files "
    "the jail never sees (D.5). Next: name a folder inside the project, such as one under an "
    "excluded root."
)
R_OUTPUT_PROTECTED = (
    "output folder {out} is or holds a protected path, such as .claude/, .github/, contracts/, "
    "service-manifest.json, the ledger or a jail_narrowing entry (0054, D.5). Next: name a "
    "folder that holds no protected path."
)
R_OUTPUT_UNCHECKED = (
    "output folder {out} could not be checked against the protected paths ({cause}). "
    "Next: fix the service manifest or the ledger declaration, then freeze again."
)
_DASHES = {"\u2013": "en dash", "\u2014": "em dash"}
# 0136 item 4: copy left in for a later edit; the list is closed, so a new form is a code change.
_PLACEHOLDERS = re.compile(
    r"\b(?:TODO|TBD|FIXME|XXX)\b|lorem ipsum|\[(?:insert|placeholder|tbd|todo)\b[^\]]*\]"
    r"|<(?:insert|placeholder)\b[^>]*>|\{\{[^}]*\}\}|\?\?\?",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"\S.*?(?:[.!?](?=\s)|(?=\n[ \t]*\n)|\Z)", re.DOTALL)
_EDGE = " \t\n.!?;:,\"'*_`#>-"


class SourcesError(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Source:
    alias: str
    role: str
    path: str
    sha256: str
    lines: int
    allowed_for: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Frozen:
    train_id: str
    output_dir: str
    private_roots: tuple[str, ...]
    sources: tuple[Source, ...]


def manifest_path(repo: Path, train: str) -> Path:
    return repo / ".claude" / "daedalus" / TRAINS_DIR / f"{train}{SUFFIX}"


def manifest_repo(path: Path) -> Path:
    # D.2: a manifest in its trains folder names its repo; any other path reads from cwd.
    parts = path.resolve().parts
    if len(parts) > 4 and parts[-4:-1] == (".claude", "daedalus", TRAINS_DIR):
        return Path(*parts[:-4])
    return project_root(Path.cwd())


def source_file(repo: Path, source: Source) -> Path:
    path = Path(source.path)
    return path if path.is_absolute() else repo / path


def _invalid(path: Path, cause: str) -> SourcesError:
    return SourcesError(
        f"MANIFEST_INVALID {path}: {cause}. Next: freeze the sources again.", EXIT_MISMATCH
    )


def _source(raw: object, path: Path) -> Source:
    if not isinstance(raw, dict):
        raise _invalid(path, "a source is not an object")
    alias, role, where, digest, lines = (
        raw.get(k) for k in ("alias", "role", "path", "sha256", "lines")
    )
    texts = (alias, role, where, digest)
    if not all(isinstance(v, str) and v for v in texts) or role not in ROLES:
        raise _invalid(path, f"source {alias!r} needs alias, a known role, path and sha256")
    if isinstance(lines, bool) or not isinstance(lines, int) or lines < 0:
        raise _invalid(path, f"source {alias} lines is not a whole number")
    topics = raw.get("allowed_for")
    if topics is not None and not (
        isinstance(topics, list) and all(isinstance(t, str) for t in topics)
    ):
        raise _invalid(path, f"source {alias} allowed_for is not a list of strings")
    allowed = None if topics is None else tuple(topics)
    return Source(str(alias), str(role), str(where), str(digest), lines, allowed)


def load_manifest(path: Path) -> Frozen:
    # D.2: the frozen sources file; any shape fault is MANIFEST_INVALID, exit 4.
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _invalid(path, f"unreadable ({exc})") from exc
    if not isinstance(raw, dict):
        raise _invalid(path, "not a JSON object")
    train, out, roots, sources = (
        raw.get(k) for k in ("train_id", "output_dir", "private_roots", "sources")
    )
    if not (isinstance(train, str) and isinstance(out, str) and os.path.isabs(out)):
        raise _invalid(path, "train_id and an absolute output_dir are required")
    if not (isinstance(roots, list) and all(isinstance(r, str) for r in roots)):
        raise _invalid(path, "private_roots is not a list of strings")
    if not isinstance(sources, list) or not sources:
        raise _invalid(path, "sources is not a non-empty list")
    parsed = tuple(_source(s, path) for s in sources)
    return Frozen(train, out, tuple(roots), parsed)


def _digest(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data.splitlines())


def _parse_source(spec: str, base: Path) -> tuple[str, str, Path, tuple[str, ...]]:
    alias, eq, rest = spec.partition("=")
    role, colon, where = rest.partition(":")
    if not eq or not colon or not where or not _ALIAS.fullmatch(alias) or role not in ROLES:
        raise SourcesError(
            f"--source {spec} is not <alias>=<role>:<path>[:<topic>,...] with a role of "
            f"{', '.join(ROLES)}. Next: write the source in that form.",
            EXIT_SHAPE,
        )
    topics: tuple[str, ...] = ()
    head, sep, tail = where.rpartition(":")
    if sep and head and _TOPICS.fullmatch(tail) and not (base / where).exists():
        where, topics = head, tuple(tail.split(","))
    path = Path(where)
    return alias, role, path if path.is_absolute() else base / path, topics


def _check_file(path: Path, alias: str, repo: Path, working: list[str]) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise SourcesError(
            f"source {alias} {path} does not exist ({exc.strerror}). Next: name a sent file.",
            EXIT_PATH,
        ) from exc
    if not stat.S_ISREG(mode):
        raise SourcesError(
            f"source {alias} {path} is not a regular file. Next: name the file, not a link.",
            EXIT_PATH,
        )
    rel = os.path.relpath(path, repo)
    if ".sent-" not in path.name and any(fnmatch.fnmatchcase(rel, g) for g in working):
        raise SourcesError(
            f"source {alias} {rel} is a working file by --working-glob. "
            "Next: freeze the sent copy, named with .sent-<date>.",
            EXIT_PATH,
        )


def _shape(specs: list[tuple[str, str, Path, tuple[str, ...]]], baselines_only: bool) -> None:
    aliases = [s[0] for s in specs]
    if len(set(aliases)) != len(aliases):
        raise SourcesError("two sources share an alias. Next: give each one alias.", EXIT_SHAPE)
    baselines = sum(1 for s in specs if s[1] == "baseline")
    if baselines_only and baselines != 2:
        raise SourcesError(
            f"--baselines-only needs exactly two baseline sources (got {baselines}). "
            "Next: name the two baselines the change logger diffs.",
            EXIT_SHAPE,
        )
    if not baselines_only and baselines > 1:
        raise SourcesError(
            "more than one source carries role baseline. Next: keep one baseline, or pass "
            "--baselines-only when no deriver runs and the change logger diffs two.",
            EXIT_SHAPE,
        )
    for alias, role, _, topics in specs:
        if role == "style" and topics:
            raise SourcesError(
                f"style source {alias} lists topics; a style source gives register only. "
                "Next: drop the topic list from that style source.",
                EXIT_SHAPE,
            )


def _roots(repo: Path) -> tuple[ExcludedRoot, ...]:
    # D.7: no command-line override; the roots come from project metadata only.
    try:
        roots = resolve_excluded_roots(load_config(str(repo)), repo)
    except (ConfigError, DataDirError) as exc:
        raise SourcesError(f"excluded_roots could not be resolved: {exc}", EXIT_ROOT) from exc
    if in_git_work_tree(repo):
        for root in roots:
            inside = _under(root.path, str(repo)) and os.path.realpath(root.path) != str(repo)
            if root.ignored is None and inside and not root_ignored(root, repo):
                raise SourcesError(
                    f"excluded root {root.path} is not ignored by git check-ignore, so git add "
                    "-A would stage it. Next: add it to .gitignore, then freeze again.",
                    EXIT_ROOT,
                )
    return roots


def output_dir_reason(out: str, repo: Path, boundary: jail.CoderBoundary | str) -> str | None:
    # D.5: output_dir bounds every document agent write, so it sits inside the project,
    # below its root, and neither is nor holds a path the coder write check protects.
    real, root = os.path.realpath(out), os.path.realpath(repo)
    if real == root:
        return R_OUTPUT_ROOT.format(out=out)
    if not real.startswith(root + os.sep):
        return R_OUTPUT_OUTSIDE.format(out=out, repo=root)
    if isinstance(boundary, str):
        return R_OUTPUT_UNCHECKED.format(out=out, cause=boundary.split(" Next:", 1)[0])
    rel = os.path.relpath(real, root).replace(os.sep, "/")
    if jail.protected_reason(rel, real, boundary) is not None:
        return R_OUTPUT_PROTECTED.format(out=out)
    return None


def _shown(path: Path, repo: Path) -> str:
    rel = os.path.relpath(path, repo)
    return path.as_posix() if rel.startswith("..") else Path(rel).as_posix()


def freeze(args: argparse.Namespace) -> tuple[Path, str, list[str]]:
    cwd = Path.cwd()
    repo = project_root(cwd)
    if not _TRAIN.fullmatch(args.train) or ".." in args.train:
        raise SourcesError(
            f"--train {args.train} is not a train id of letters, digits, dot, dash and "
            "underscore. Next: pass the train id.",
            EXIT_SHAPE,
        )
    specs = [_parse_source(s, cwd) for s in args.source]
    _shape(specs, args.baselines_only)
    sources: list[dict[str, object]] = []
    for alias, role, path, topics in specs:
        _check_file(path, alias, repo, args.working_glob or [])
        digest, lines = _digest(path)
        entry: dict[str, object] = {
            "alias": alias,
            "role": role,
            "path": _shown(path, repo),
            "sha256": digest,
            "lines": lines,
        }
        if role in {"amendment", "style"} or topics:
            entry["allowed_for"] = list(topics)
        sources.append(entry)
    roots = _roots(repo)
    out = os.path.normpath(
        Path(args.output_dir) if os.path.isabs(args.output_dir) else cwd / args.output_dir
    )
    bad = output_dir_reason(out, repo, jail._coder_boundary(str(repo), load_config(str(repo))))
    if bad is not None:
        raise SourcesError(bad, EXIT_PATH)
    notes = [] if roots else ["[EXCLUDED_ROOTS: none declared]"]
    if not any(_under(out, r.path) for r in roots):
        notes.append(
            f"warning: output_dir {out} is under no excluded root, so it may be committed."
        )
    doc = {
        "train_id": args.train,
        "frozen_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output_dir": out.rstrip(os.sep) + os.sep,
        "private_roots": [r.path.rstrip(os.sep) + os.sep for r in roots],
        "sources": sources,
    }
    text = json.dumps(doc, indent=2) + "\n"
    try:
        trains = check_project_data_dir(str(cwd)) / TRAINS_DIR
    except DataDirError as exc:
        raise SourcesError(f"the project data folder is not usable: {exc}", EXIT_ROOT) from exc
    trains.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic.refuse_links(trains)
    target = manifest_path(repo, args.train)
    atomic.write_atomic(target, text, 0o600)
    return target, text, notes


def _sentences(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for match in _SENTENCE.finditer(text):
        norm = " ".join(match.group(0).split()).casefold().strip(_EDGE)
        if norm:
            out.append((text.count("\n", 0, match.start()) + 1, norm))
    return out


def _outputs(frozen: Frozen, repo: Path) -> list[Path]:
    sources = {os.path.realpath(source_file(repo, s)) for s in frozen.sources}
    found: list[Path] = []
    for folder, dirs, files in os.walk(frozen.output_dir):
        dirs.sort()
        for name in sorted(files):
            path = Path(folder) / name
            if path.is_file() and not path.is_symlink() and os.path.realpath(path) not in sources:
                found.append(path)
    return found


def _lint(frozen: Frozen, repo: Path) -> list[str]:
    # 0136 items 4 and 5: dashes, placeholder copy, and style sentences carrying a number.
    styled: list[tuple[str, int, str]] = []
    for source in frozen.sources:
        if source.role != "style":
            continue
        text = source_file(repo, source).read_text(encoding="utf-8", errors="replace")
        styled += [(source.alias, n, s) for n, s in _sentences(text) if re.search(r"\d", s)]
    findings: list[str] = []
    for path in _outputs(frozen, repo):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for char, name in _DASHES.items():
                if char in line:
                    findings.append(f"DASH {path}:{number} {name}")
            for hit in _PLACEHOLDERS.finditer(line):
                findings.append(f"PLACEHOLDER {path}:{number} {hit.group(0)}")
        for number, sentence in _sentences(text):
            for alias, at, style in styled:
                if style in sentence:
                    findings.append(f"STYLE {path}:{number} matches {alias}:{at} {style}")
    return findings


def verify(path: Path) -> tuple[int, list[str]]:
    frozen = load_manifest(path)
    repo = manifest_repo(path)
    lines: list[str] = []
    bad = False
    for source in frozen.sources:
        target = source_file(repo, source)
        try:
            if not stat.S_ISREG(os.lstat(target).st_mode):
                raise OSError("not a regular file")
            digest, count = _digest(target)
        except OSError as exc:
            lines.append(f"MISMATCH {source.alias} {source.path}: {exc}")
            bad = True
            continue
        if (digest, count) != (source.sha256, source.lines):
            lines.append(
                f"MISMATCH {source.alias} {source.path}: sha256 {digest} lines {count}, "
                f"frozen sha256 {source.sha256} lines {source.lines}"
            )
            bad = True
        else:
            lines.append(f"OK   {source.alias} {source.path}")
    if bad:
        return EXIT_MISMATCH, [*lines, "[STATUS: MANIFEST_INVALID]"]
    # 99: the lint walks output_dir, so a hand-edited manifest is bounded before the walk.
    try:
        boundary = jail._coder_boundary(str(repo), load_config(str(repo)))
    except (ConfigError, DataDirError) as exc:
        raise SourcesError(f"project metadata could not be read: {exc}", EXIT_ROOT) from exc
    reason = output_dir_reason(frozen.output_dir, repo, boundary)
    if reason is not None:
        return EXIT_PATH, [*lines, reason]
    findings = _lint(frozen, repo)
    if findings:
        return EXIT_LINT, [*lines, *findings, f"verify: {len(findings)} output finding(s)"]
    return 0, [*lines, "verify: sources match and outputs are clean"]


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="freeze_sources.py", description=DESCRIPTION)
    parser.add_argument("--verify", metavar="MANIFEST", type=Path)
    parser.add_argument("--train")
    parser.add_argument("--output-dir")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--baselines-only", action="store_true")
    parser.add_argument("--working-glob", action="append")
    args = parser.parse_args(argv)
    freezing = args.train or args.output_dir or args.source or args.baselines_only
    if args.verify is not None and (freezing or args.working_glob):
        parser.error("--verify takes only the manifest path")
    if args.verify is None and not (args.train and args.output_dir and args.source):
        parser.error("--train, --output-dir and at least one --source are required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    try:
        if args.verify is not None:
            code, lines = verify(args.verify)
            print("\n".join(lines))
            return code
        target, text, notes = freeze(args)
    except SourcesError as exc:
        print(f"freeze_sources: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"freeze_sources: {exc}. Next: check the paths and permissions.", file=sys.stderr)
        return EXIT_PATH
    for note in notes:
        print(note, file=sys.stderr)
    print(f"wrote {target}", file=sys.stderr)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
