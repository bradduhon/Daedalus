# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0259: the main session's note classes, an allow list of what earns a note during a run.
# A main-session call no row names runs with no note and its audit record says allow.
# Rows ruled 1 to 3 are the ruling's short list; the rest await the operator's ruling.
from __future__ import annotations

import os
from dataclasses import dataclass

LEAD = "Warning: "
RULED_CREDENTIAL = "ruled 1: reading or searching a credential file"
RULED_PROTECTED = "ruled 2: writing into the run's protected folders"
RULED_PUSH = "ruled 3: a push or a merge outside the release phase"
NEEDS_RULING = "needs ruling"


@dataclass(frozen=True)
class NoteClass:
    name: str
    ruled: str
    seen: str
    next: str
    check: str

    def text(self, what: str, step: str = "", **extra: str) -> str:
        return f"{LEAD}{self.seen.format(what=what, **extra)} Next: {step or self.next}"


@dataclass(frozen=True)
class Note:
    klass: NoteClass
    text: str
    # 0259: the check's own finding, kept for the audit record and never shown to the session.
    detail: str = ""


CREDENTIAL_READ = NoteClass(
    "credential_read",
    RULED_CREDENTIAL,
    "{what} reaches a credential file, a .env file or the run's reply key, or a path the "
    "plugin cannot rule out as one, so a secret can land in this transcript.",
    "leave the file unread here, and read it from your own shell if the work needs it.",
    "lib.credential_paths.path_reason, lib.jail._bash_credential_reason, "
    "lib.session_reading.unread_note",
)
PROTECTED_WRITE = NoteClass(
    "protected_folder_write",
    RULED_PROTECTED,
    "{what} the run's protected folder (.claude/daedalus or the plugin's data folder). That "
    "folder holds the audit log, the run state and the reply key. A change made by hand breaks "
    "the record that proves the audit happened.",
    "leave that folder to the plugin's own scripts.",
    "lib.jail.integrity_reason, lib.shell._git_reason, lib.session_reading.unread_note",
)
PUSH_OR_MERGE = NoteClass(
    "push_or_merge",
    RULED_PUSH,
    "{what}. A run is active and is not in its release phase, so work can reach the remote "
    "before the run's audit approves it.",
    "let the release phase push and open the pull request; the operator merges.",
    "lib.gh_policy.classify, lib.shell._git_reason, lib.session_reading.unread_note",
)
CREDENTIAL_WRITE = NoteClass(
    "credential_write",
    NEEDS_RULING,
    "{what} writes a credential file or a .env file, or an ignore file that opens one. A "
    "wrong write can replace a key or leave a secret behind.",
    "make that change from your own shell.",
    "lib.credential_paths.path_reason",
)
GIT_METADATA_WRITE = NoteClass(
    "git_metadata_write",
    NEEDS_RULING,
    "{what} writes inside .git, the repository's own metadata. A wrong write corrupts the clone.",
    "change the repository through git commands.",
    "lib.jail.integrity_reason",
)
MAIN_CHECKOUT_WRITE = NoteClass(
    "main_checkout_write",
    NEEDS_RULING,
    "{what} lands in the main checkout while run {train} works in unit worktrees. It can leave "
    "a dirty tree that stops the run's finish step, or clash with a unit branch.",
    "make the change in a unit worktree, or after the run.",
    "lib.jail._main_write_train",
)
DISPATCH_RULE = NoteClass(
    "dispatch_rule",
    NEEDS_RULING,
    "{what} skips a rule the run checks each time it starts an agent, so the agent starts "
    "without it. The audit log keeps the rule it skipped.",
    "read the run's audit report for that rule, and start the agent again inside it if the "
    "work needs the run's guarantees.",
    "lib.dispatch_binding._dispatch_reason",
)
RESUME_RULE = NoteClass(
    "resume_rule",
    NEEDS_RULING,
    "{what} skips the run's unit binding check. The message goes out and the agent keeps its "
    "unit. The audit log keeps the rule it skipped.",
    "read the run's audit report for that rule before you rely on the agent's unit.",
    "lib.dispatch_binding.main_resume_reason",
)
EXCLUDED_FOLDER = NoteClass(
    "excluded_folder",
    NEEDS_RULING,
    "{what} would put a file from a folder the project excludes into git, GitHub or a file write.",
    "keep files from that folder out of git, gh and redirects.",
    "lib.jail._main_excluded",
)
EXCLUDED_UNCHECKED = NoteClass(
    "excluded_folder_unchecked",
    NEEDS_RULING,
    "The project's excluded folders could not be resolved, so {what} went unchecked against them.",
    "fix git_excluded_folders in .claude/daedalus/config.json.",
    "lib.jail._main_excluded",
)
NESTED_SESSION = NoteClass(
    "nested_session",
    NEEDS_RULING,
    "{what} starts a nested Claude session. Its calls are judged as yours, with none of an "
    "agent's limits.",
    "start nested sessions from your own shell.",
    "lib.jail.claude_word, lib.shell.R_CLAUDE_PATH, lib.session_reading.unread_note",
)
SIGNING = NoteClass(
    "signing",
    NEEDS_RULING,
    "{what} signs a commit or a tag with the operator's key.",
    "leave the commit unsigned; the operator signs from their own shell.",
    "lib.shell._git_reason",
)
GIT_CONFIG_KEY = NoteClass(
    "git_config_key",
    NEEDS_RULING,
    "{what} sets a git option that changes push, hook, pager, ssh, protocol or alias "
    "behaviour, which can run another program.",
    "run git without that option.",
    "lib.shell._git_reason",
)
GITHUB_CHANGE = NoteClass(
    "github_change",
    NEEDS_RULING,
    "{what} while a run is active.",
    "make that change after the run, or from your own shell.",
    "lib.gh_policy.class_reason, lib.session_reading.unread_note",
)
DESTRUCTIVE_DELETE = NoteClass(
    "destructive_delete",
    NEEDS_RULING,
    "{what} deletes recursively from the root or home folder, or a folder above home. Neither "
    "git nor the plugin can restore those files.",
    "delete the files you mean by name.",
    "lib.shell._rm_reason",
)
LOOKUP_VARIABLE = NoteClass(
    "lookup_variable",
    NEEDS_RULING,
    "{what} changes a variable that decides which program later commands run, such as PATH "
    "or LD_PRELOAD, so the plugin cannot tell what those commands do.",
    "leave that variable unchanged here, and set it from your own shell if the work needs it.",
    "lib.admit.LOOKUP_VARS, lib.session_reading.unread_note",
)
NO_WORKING_FOLDER = NoteClass(
    "no_working_folder",
    NEEDS_RULING,
    "The hook received no working folder, so the plugin cannot tell which repository {what} "
    "touches.",
    "report this to the operator.",
    "lib.jail.integrity_reason",
)
# 0259: the typed table; a test reads every row, and nothing outside it earns a note.
NOTE_CLASSES: tuple[NoteClass, ...] = (
    CREDENTIAL_READ,
    PROTECTED_WRITE,
    PUSH_OR_MERGE,
    CREDENTIAL_WRITE,
    GIT_METADATA_WRITE,
    MAIN_CHECKOUT_WRITE,
    DISPATCH_RULE,
    RESUME_RULE,
    EXCLUDED_FOLDER,
    EXCLUDED_UNCHECKED,
    NESTED_SESSION,
    SIGNING,
    GIT_CONFIG_KEY,
    GITHUB_CHANGE,
    DESTRUCTIVE_DELETE,
    LOOKUP_VARIABLE,
    NO_WORKING_FOLDER,
)


def tool_what(tool: str, tool_input: dict[str, object], cwd: str) -> str:
    # 0259: the subject of a main-session note, in plain words.
    if tool == "Bash":
        return "This command"
    raw = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path")
    named = raw or (tool_input.get("pattern") if tool == "Glob" else None)
    if isinstance(named, str) and named:
        shown = os.path.normpath(os.path.join(cwd, named)) if os.path.isabs(cwd) else named
        return f"This {tool} of {shown}"
    return f"This {tool} call"


def note(klass: NoteClass, what: str, detail: str = "", step: str = "", **extra: str) -> Note:
    return Note(klass, klass.text(what, step, **extra), detail)


def rule_step(finding: str) -> str:
    # 0259: a dispatch rule's own next step, kept only when it holds no refusal wording.
    _, sep, step = finding.rpartition("Next:")
    step = step.strip()
    return step if sep and step and "refus" not in step.casefold() else ""


def record_reason(found: Note) -> str:
    # 0259: the audit row carries the class name and the note; the check's finding trails it.
    text = f"{found.klass.name}: {found.text}"
    return f"{text} Detail: {found.detail}" if found.detail else text
