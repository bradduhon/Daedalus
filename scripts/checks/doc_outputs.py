# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0135, D.5: doc-deriver and change-logger write only under the active document train's
# output_dir, and never to a source its frozen sources file lists.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import freeze_sources  # noqa: E402
from lib import hook_io, jail, shell  # noqa: E402
from lib.audit import project_root  # noqa: E402
from lib.train_state import active_train  # noqa: E402

TOOLS: frozenset[str] = frozenset(jail.WRITE_TOOLS | {"Bash"})
FLAGS: dict[str, hook_io.Flag] = {}
PARSER = hook_io.build_parser(Path(__file__).stem, FLAGS)
R_NO_TRAIN = (
    "no train is active in {repo}, so no document output folder is known (D.5). "
    "Next: start the document train and freeze its sources first."
)
R_NO_MANIFEST = (
    "train {train} has no frozen sources file at {path} (D.7). "
    "Next: run freeze_sources.py --train {train} before dispatching a document agent."
)
R_OUTSIDE = (
    "document agents write only under the train's output folder {out}: {path} (D.5). "
    "Next: write the output there."
)
R_SOURCE = (
    "{path} is source {alias} of train {train}, and sources stay unchanged during the train "
    "(D.5). Next: write the output under {out}."
)


def _reason(
    path: str, frozen: freeze_sources.Frozen, repo: Path, boundary: jail.CoderBoundary | str
) -> str | None:
    for source in frozen.sources:
        if jail._same_path(path, str(freeze_sources.source_file(repo, source))):
            return R_SOURCE.format(
                path=path, alias=source.alias, train=frozen.train_id, out=frozen.output_dir
            )
    if not shell._under(path, frozen.output_dir):
        return R_OUTSIDE.format(out=frozen.output_dir, path=path)
    # 0054: the coder write check's protected list binds here too, inside the output folder,
    # which output_dir_reason already holds below the project root.
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(repo)).replace(os.sep, "/")
    return jail.protected_reason(rel, path, boundary)


def judge(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    cwd = hook_io.text(hook_input, "cwd")
    if not os.path.isabs(cwd):
        return jail.R_NO_CWD
    repo = project_root(cwd)
    train = active_train(repo)
    if train is None:
        return R_NO_TRAIN.format(repo=repo)
    path = freeze_sources.manifest_path(repo, train)
    if not path.is_file():
        return R_NO_MANIFEST.format(train=train, path=path)
    try:
        frozen = freeze_sources.load_manifest(path)
    except freeze_sources.SourcesError as exc:
        return str(exc)
    boundary = jail._coder_boundary(cwd, hook_io.hook_config(cwd))
    # D.5: a sources file frozen before the output bound existed meets the same bound here.
    bad = freeze_sources.output_dir_reason(frozen.output_dir, repo, boundary)
    if bad is not None:
        return bad
    if hook_io.text(hook_input, "tool_name") in jail.WRITE_TOOLS:
        target = shell._abs(hook_io.write_path(hook_input), cwd)
        return _reason(target, frozen, repo, boundary)
    segments = shell.worker_segments(hook_io.text(hook_io.tool_input(hook_input), "command"))
    if segments is None:
        return shell.R_UNSUPPORTED
    for segment in filter(None, segments):
        for target in jail._coder_write_targets(segment, cwd):
            reason = _reason(target, frozen, repo, boundary)
            if reason:
                return reason
    return None


decide, main = hook_io.entrypoint(judge, TOOLS, PARSER)

if __name__ == "__main__":
    sys.exit(main())
