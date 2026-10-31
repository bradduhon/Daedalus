# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Plan 10 spec 3.2: every path the plugin can write, one row per path and writer function.
# tests/test_inventory.py walks scripts/ with ast and holds this table equal to the write sites.
from __future__ import annotations

from typing import NamedTuple


class Entry(NamedTuple):
    pattern: str
    writer: str
    when: str


_DATA = "<repo>/.claude/daedalus"
_TRAINS = f"{_DATA}/trains"
_AUDIT = f"{_DATA}/audit"
_SCRATCH = "<repo>/docs/.tmp/daedalus"
_FRAMEWORKS = "<cache>/frameworks/<family>"
_CONFINE = "$TMPDIR/daedalus-confine-<uid>/<16 hex>"
_BRANCH = "refs/heads/daedalus/<train-id>"
_UNIT = "refs/heads/daedalus-unit/<train-id>-<unit-slug>"
_AUDIT_UNIT = "refs/heads/daedalus-unit/<train-id>-audit"
_WS = "scripts/lib/workspace.py"

FILES: tuple[Entry, ...] = (
    Entry(
        "<ledger repo>/.claude/daedalus/ledger-locks/",
        "scripts/append_ledger.py:_lock_path",
        "a ledger entry is appended",
    ),
    Entry(
        "<ledger repo>/.claude/daedalus/ledger-locks/<16 hex>.lock",
        "scripts/append_ledger.py:_append",
        "a ledger entry is appended; held while the row is written",
    ),
    Entry(
        "<ledger file>",
        "scripts/append_ledger.py:_append",
        "an approved Build Train appends one row per ruling",
    ),
    Entry(
        "<--out file>",
        "scripts/audit_report.py:_write_report",
        "you run audit_report.py with --out; refused inside any .claude/daedalus folder",
    ),
    Entry(
        "<charter_root>/reports/<date>-tokens-<run id>.md",
        "scripts/audit_report.py:_write_report",
        "you run token_economy.py report --save and config.json declares charter_root",
    ),
    Entry(
        f"{_SCRATCH}/<run id>/tokens.md",
        "scripts/audit_report.py:_write_report",
        "you run token_economy.py report --save with no charter_root declared",
    ),
    Entry(
        f"{_CONFINE}/",
        "scripts/daedalus_confine.py:_private_tmp",
        "a command runs under the kernel wrapper; outside the project, one folder per worktree",
    ),
    Entry(
        f"{_CONFINE}/gitconfig",
        "scripts/daedalus_confine.py:_tool_env",
        "a command runs under the kernel wrapper; an empty git config, rewritten each run",
    ),
    Entry(
        f"{_CONFINE}/config/",
        "scripts/daedalus_confine.py:_tool_env",
        "a command runs under the kernel wrapper; an empty config home",
    ),
    Entry(
        "<repo>/<--out>/map.md",
        "scripts/daedalus_map.py:main",
        "you run daedalus_map.py without --check; the --out folder is created first",
    ),
    Entry(
        "<repo>/<--out>/map.json",
        "scripts/daedalus_map.py:main",
        "you run daedalus_map.py without --check",
    ),
    Entry(
        "<repo>/service-manifest.json",
        "scripts/daedalus_setup.py:_write_new",
        "you run /daedalus:setup and the file is missing",
    ),
    Entry(
        f"{_DATA}/config.json",
        "scripts/daedalus_setup.py:_write_new",
        "you run /daedalus:setup and the file is missing",
    ),
    Entry(
        f"{_TRAINS}/",
        "scripts/freeze_sources.py:freeze",
        "a document train freezes its sources",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.sources.json",
        "scripts/freeze_sources.py:freeze",
        "a document train freezes its sources",
    ),
    Entry(
        "<--out folder>/controls.json",
        "scripts/import_pack.py:write_pack",
        "you run import_pack.py; written before pack.json, and the --out folder is created first",
    ),
    Entry(
        "<--out folder>/pack.json",
        "scripts/import_pack.py:write_pack",
        "you run import_pack.py; written last, so the folder reads as a pack only when whole",
    ),
    Entry(
        "<target folder>/.<target name>.<16 hex>.tmp",
        "scripts/lib/atomic.py:_temp",
        "every atomic or create-once write; renamed onto the target or removed before it returns",
    ),
    Entry(
        "<target each caller names>",
        "scripts/lib/atomic.py:write_atomic",
        "every atomic write; the caller's own row names the target",
    ),
    Entry(
        f"{_DATA}/",
        "scripts/lib/audit.py:ensure_project_data_dir",
        "a hook records an event while a train runs, or a ledger entry is appended",
    ),
    Entry(
        f"{_DATA}/.gitignore",
        "scripts/lib/audit.py:ensure_project_data_dir",
        "the data folder is first used; holds * so git ignores the folder",
    ),
    Entry(
        f"{_DATA}/.reply-hmac.key.<random>",
        "scripts/lib/audit.py:_make_reply_key",
        "the first agent reply recorded during a train; linked to reply-hmac.key, then removed",
    ),
    Entry(
        f"{_DATA}/reply-hmac.key",
        "scripts/lib/audit.py:_make_reply_key",
        "the first agent reply recorded during a train; no agent may read it",
    ),
    Entry(
        f"{_AUDIT}/",
        "scripts/lib/audit.py:audit_append",
        "a hook records an event while a train runs",
    ),
    Entry(
        f"{_AUDIT}/<session_id>.jsonl",
        "scripts/lib/audit.py:_chain_write",
        "a hook records an event while a train runs; one hash-chained line per event",
    ),
    Entry(
        f"{_AUDIT}/<session_id>.lock",
        "scripts/lib/audit.py:audit_lock",
        "each write or read of that session's audit log",
    ),
    Entry(
        f"{_AUDIT}/<session_id>.lock",
        "scripts/lib/audit.py:_try_lock",
        "old audit logs are rotated out under audit_retention_days",
    ),
    Entry(
        f"{_AUDIT}/<session_id>.skipped",
        "scripts/lib/audit.py:_count_skipped",
        "a forked subagent stops; counts the stops the log could not record",
    ),
    Entry(
        f"{_FRAMEWORKS}/",
        "scripts/lib/fetch.py:_prepare_dest",
        "you run refresh_frameworks.py; outside the project, folders made at mode 0700",
    ),
    Entry(
        f"{_FRAMEWORKS}/.refresh.lock",
        "scripts/lib/fetch.py:_locked",
        "you run refresh_frameworks.py; held for the whole refresh",
    ),
    Entry(
        f"{_FRAMEWORKS}/.<file>-<random>.tmp",
        "scripts/lib/fetch.py:_temp",
        "you run refresh_frameworks.py; each download, renamed into place or removed at the end",
    ),
    Entry(
        "<lock file each caller names>",
        "scripts/lib/locks.py:open_lock",
        "every lock a caller takes; the caller's own row names the lock file",
    ),
    Entry(
        "<lock file each caller names>",
        "scripts/lib/locks.py:locked",
        "every lock a caller takes; the caller's own row names the lock file",
    ),
    Entry(
        "<--output or --out folder>",
        "scripts/lib/workspace.py:make_output",
        "start with --output or the folder begin with --out; a relative folder is under <repo>",
    ),
    Entry(
        f"{_SCRATCH}/<train-id>/briefs/<stage>-<n>.md",
        "scripts/lib/train_runner.py:_render",
        "the train runner dispatches a stage; one brief per dispatch",
    ),
    Entry(
        f"{_SCRATCH}/<train-id>/replies/",
        "scripts/lib/train_runner.py:_render",
        "the train runner dispatches a stage; the folder its reply lands in",
    ),
    Entry(
        f"{_TRAINS}/",
        "scripts/lib/train_state.py:_state_dir",
        "the first train state or unit binding write",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.lock",
        "scripts/lib/train_state.py:locked_file",
        "each train state change",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.bindings.lock",
        "scripts/lib/train_state.py:locked_file",
        "each unit binding change",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.writers.lock",
        "scripts/lib/train_state.py:locked_file",
        "each writer dispatch, and each writer's first call",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.json",
        "scripts/lib/train_state.py:_write",
        "a Build Train starts and at each state change, the contract skip record included",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.bindings.json",
        "scripts/lib/train_state.py:_write",
        "the first coder of a train is dispatched, and at each binding change",
    ),
    Entry(
        f"{_TRAINS}/<train-id>.writers.json",
        "scripts/lib/train_state.py:_write",
        "a writer is dispatched, and its first call binds the kind its dispatch recorded",
    ),
    Entry(
        f"{_SCRATCH}/<train-id>-summary.md",
        "scripts/lib/train_summary.py:write_summary",
        "a train ends or stops",
    ),
    Entry(
        "<repo>/.claude/worktrees/<train-id>-<unit-slug>",
        f"{_WS}:create",
        "the Build Train starts a unit; removed when the train ends or stops",
    ),
    Entry(_UNIT, f"{_WS}:create", "the Build Train starts a unit; kept after the train ends"),
    Entry(
        "<repo>/.claude/worktrees/<train-id>-audit",
        f"{_WS}:create",
        "the audit stage starts",
    ),
    Entry(
        "<repo>/.claude/worktrees/<train-id>-docstage",
        f"{_WS}:create",
        "the docs stage starts",
    ),
    Entry(
        "<repo>/.claude/worktrees/<train-id>-audit",
        f"{_WS}:_audit_readd",
        "a train continues past a recorded verdict and the audit worktree is added again",
    ),
    Entry(
        _AUDIT_UNIT,
        f"{_WS}:_audit_readd",
        "the audit worktree is added again and its branch is missing",
    ),
    Entry(
        _AUDIT_UNIT,
        f"{_WS}:refresh",
        "the audit worktree is refreshed; a fast-forward to the integration branch",
    ),
    Entry(
        "<repo>/.claude/worktrees/",
        f"{_WS}:_ensure_marker",
        "the first worktree is created",
    ),
    Entry(
        "<repo>/.claude/worktrees/.gitignore",
        f"{_WS}:_ensure_marker",
        "the first worktree is created; holds * so git ignores every worktree there",
    ),
    Entry(
        _BRANCH,
        f"{_WS}:_charter_branch",
        "a Build Train begins with charter_root set; the branch is made in the Charter",
    ),
    Entry(
        _BRANCH,
        f"{_WS}:_on_branch",
        "lock, lock --no-contract after a contract skip, merge or resume; made if missing",
    ),
    Entry(
        _BRANCH,
        f"{_WS}:lock",
        "the contract is locked or revised; one commit of contracts/<name>.md",
    ),
    Entry(
        _BRANCH,
        f"{_WS}:_merge",
        "a wave merges; one merge commit per unit branch",
    ),
    Entry(
        _BRANCH,
        f"{_WS}:_drop_empty",
        "a train stops while its branch holds no commit past the base; deletes it with -d",
    ),
    Entry(
        f"{_DATA}/train.active",
        f"{_WS}:mark_train",
        "a Build Train begins or resumes; removed when the train ends or stops",
    ),
    Entry(
        f"{_SCRATCH}/",
        f"{_WS}:_scratch",
        "a Build Train begins, or the release step writes its notes",
    ),
    Entry(
        f"{_SCRATCH}/.gitignore",
        f"{_WS}:_scratch",
        "the scratch folder is first made; holds * so git ignores it",
    ),
    Entry(
        f"{_SCRATCH}/<train-id>/release-notes.md",
        f"{_WS}:_write_notes",
        "the release step runs",
    ),
    Entry(
        f"{_FRAMEWORKS}/<file>",
        "scripts/refresh_frameworks.py:run_adapter",
        "you run refresh_frameworks.py; replaced only after every download checks",
    ),
    Entry(
        f"{_FRAMEWORKS}/manifest.json",
        "scripts/refresh_frameworks.py:run_adapter",
        "you run refresh_frameworks.py; replaced last",
    ),
    Entry(
        "<--out file>",
        "scripts/standing_rules.py:main",
        "you run standing_rules.py without --check",
    ),
)


def lines() -> list[str]:
    # Spec 3.2 item 1: `<path pattern> | <writer> | <when>`, one line per FILES row.
    return [f"{e.pattern} | {e.writer} | {e.when}" for e in FILES]
