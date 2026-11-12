# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0259: the main session's short list of note classes; everything else runs with no note.
from __future__ import annotations

import importlib
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

import enforce_agent_jail
import pytest
from lib import config, dispatch_binding, jail, session_reading, train_runner, train_state
from lib import session_notes as notes
from lib.jail import KNOWN_AGENTS, decide

from tests import hook_chain
from tests.conftest import CFG, CWD, WT, audit_records, main_warning, write_train_marker
from tests.jail_cases import seed_train
from tests.payloads import _b, _cred, _w

DEL = "r" + "m -rf"
# 0259: the live run's commands that drew notes from the agents' table, and their refusal.
LIVE_RUN = (
    "python3 $D/daedalus_train.py summary --repo /work/repo",
    "echo hi",
    "cut -d: -f1 notes.txt",
    "terraform init -backend=false",
)
# 0259: the coder's own table admits echo; the other three it refuses, unchanged.
CODER_REFUSED = frozenset(LIVE_RUN) - {"echo hi"}


def _noted(d: jail.Decision, klass: notes.NoteClass) -> bool:
    reason = str(d.reason)
    return d.warn and not d.allow and d.note == klass.name and reason.startswith("Warning: ")


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize("command", LIVE_RUN)
def test_a_live_run_command_draws_no_note_from_main_and_a_refusal_from_a_coder(
    command: str,
) -> None:
    assert not jail.admitted(command, "main", CWD), command
    d = decide(_b(None, command), CFG)
    assert d.allow and not d.warn and d.reason is None and d.note is None, (command, d)
    if command in CODER_REFUSED:
        coder = hook_chain.decide(_cred("coder", "Bash", WT, command=command), CFG)
        assert not coder.allow and not coder.warn and coder.reason, (command, coder)


@pytest.mark.parametrize("command", LIVE_RUN)
def test_a_live_run_command_runs_silent_and_records_allow(
    run_script: Any, project_data: Path, hook_input: Any, command: str
) -> None:
    write_train_marker(project_data.parent.parent)
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": command}))
    assert (result.returncode, result.stdout, result.stderr) == (0, "", ""), result
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and rec["reason"] is None, rec


def test_the_note_table_is_typed_and_complete() -> None:
    names = [k.name for k in notes.NOTE_CLASSES]
    assert len(names) == len(set(names)), names
    ruled = {notes.RULED_CREDENTIAL, notes.RULED_PROTECTED, notes.RULED_PUSH}
    assert {k.ruled for k in notes.NOTE_CLASSES} == ruled | {notes.NEEDS_RULING}
    assert [k.name for k in notes.NOTE_CLASSES if k.ruled in ruled] == [
        "credential_read",
        "protected_folder_write",
        "push_or_merge",
    ]
    for klass in notes.NOTE_CLASSES:
        for check in klass.check.split(", "):
            module, _, attr = check.rpartition(".")
            assert hasattr(importlib.import_module(module), attr), (klass.name, check)


_AGENT_WORDS = re.compile(
    r"\b(" + "|".join(sorted(KNOWN_AGENTS - {"main"}, key=len, reverse=True)) + r")\b"
)


def _session_texts() -> list[str]:
    texts = [k.text("This command", train="20261015-120000") for k in notes.NOTE_CLASSES]
    leads = (
        enforce_agent_jail._LOAD_WARN,
        enforce_agent_jail._AUDIT_WARN,
        enforce_agent_jail._CONFIG_WARN,
        enforce_agent_jail._JUDGE_WARN,
    )
    return texts + [lead.format(tool="Bash") for lead in leads]


@pytest.mark.parametrize("text", _session_texts())
def test_no_main_session_note_says_refused_or_names_an_agent_rule(text: str) -> None:
    assert text.startswith("Warning: "), text
    assert "refused" not in text.casefold(), text
    assert _AGENT_WORDS.search(text) is None, text


def test_every_note_ends_with_its_next_step() -> None:
    for klass in notes.NOTE_CLASSES:
        text = klass.text("This command", train="20261015-120000")
        assert text.endswith(f"Next: {klass.next}") and klass.next.endswith("."), klass.name


def test_a_rule_step_with_refusal_wording_falls_back_to_the_class_step() -> None:
    assert notes.rule_step("x. Next: name one unit.") == "name one unit."
    assert notes.rule_step("x. Next: a refused writer waits.") == ""
    assert notes.rule_step("no step here") == ""


def _trigger(name: str, home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    # 0259: one main-session call per note class, judged in the fake train repo.
    agent = {"tool_name": "Agent", "tool_input": {"prompt": "x"}, "cwd": CWD}
    resume = {"tool_name": "SendMessage", "tool_input": {"to": "c1", "message": "x"}, "cwd": CWD}
    found = "Next: name one unit."
    monkeypatch.setattr(dispatch_binding, "_dispatch_reason", lambda *a, **k: found)
    monkeypatch.setattr(dispatch_binding, "main_resume_reason", lambda *a, **k: found)
    return {
        "credential_read": _cred(None, "Read", file_path=f"{home}/.ssh/id_ed25519"),
        "protected_folder_write": _w(None, f"{CWD}/.claude/daedalus/config.json"),
        "push_or_merge": _b(None, "git push --force origin feature/x"),
        "credential_write": _w(None, f"{home}/.ssh/config"),
        "git_metadata_write": _w(None, f"{CWD}/.git/config"),
        "main_checkout_write": _w(None, f"{CWD}/src/app.py"),
        "dispatch_rule": agent,
        "resume_rule": resume,
        "excluded_folder": _b(None, "git add notes/a.md"),
        "excluded_folder_unchecked": _b(None, "git add notes/a.md"),
        "signing": _b(None, "git commit -S -m x"),
        "git_config_key": _b(None, "git -c core.pager=x log"),
        "destructive_delete": _b(None, f"{DEL} /"),
    }[name]


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize("klass", notes.NOTE_CLASSES, ids=lambda k: k.name)
def test_each_note_class_notes_main_and_keeps_its_class_on_the_record(
    klass: notes.NoteClass, cred_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if klass is notes.EXCLUDED_FOLDER:
        monkeypatch.setattr(jail, "excluded_root_reason", lambda *a, **k: "notes is excluded")
    if klass is notes.EXCLUDED_UNCHECKED:

        def broken(*_args: object, **_kwargs: object) -> str:
            raise config.ConfigError("roots unreadable")

        monkeypatch.setattr(jail, "excluded_root_reason", broken)
    d = decide(_trigger(klass.name, cred_home, monkeypatch), CFG)
    assert _noted(d, klass), (klass.name, d)
    assert d.record is not None and d.record.startswith(f"{klass.name}: {d.reason}"), d.record
    assert "Next: " in str(d.reason) and "refused" not in str(d.reason).casefold(), d.reason


@pytest.mark.parametrize(
    ("command", "klass"),
    [
        ("git push -u origin feature/x", "push_or_merge"),
        ("git add .claude/daedalus/config.json", "protected_folder_write"),
        ("cat ~/.ssh/id_ed25519", "credential_read"),
        ("gh pr merge 5", "push_or_merge"),
    ],
)
def test_a_noted_call_runs_and_records_warn_with_its_class_and_note(
    run_script: Any,
    project_data: Path,
    hook_input: Any,
    cred_home: Path,
    command: str,
    klass: str,
) -> None:
    (cred_home / ".ssh").mkdir()
    write_train_marker(project_data.parent.parent)
    payload = hook_input(tool_input={"command": command})
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and result.stderr == "", result
    note = main_warning(result.stdout)
    assert note.startswith("Warning: ") and "refused" not in note.casefold(), note
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "warn", rec
    assert str(rec["reason"]).startswith(f"jail: {klass}: {note}"), rec["reason"]


def test_the_credential_note_outside_a_run_takes_the_new_wording(
    run_script: Any, repo_cwd: Path, hook_input: Any, cred_home: Path
) -> None:
    key = cred_home / ".ssh" / "id_ed25519"
    result = run_script(
        "enforce_agent_jail.py", hook_input(tool_name="Read", tool_input={"file_path": str(key)})
    )
    assert result.returncode == 0, result.stderr
    assert main_warning(result.stdout) == notes.CREDENTIAL_READ.text(f"This Read of {key}")
    assert not (repo_cwd / ".claude").exists()


# 0259 self-hunt: forms that drew the agents' table refusal before and must still be noted.
HUNT = (
    ("cat ~/.ssh/id_ed25519", "credential_read"),
    ("bash -c 'cat ~/.ssh/id_ed25519'", "credential_read"),
    ("D=~/.ssh; cat $D/id_ed25519", "credential_read"),
    ("export D=~/.aws; cat $D/credentials", "credential_read"),
    ("cat ~/.{a..z}ws/credentials", "credential_read"),
    ("git show HEAD:.env | head", "credential_read"),
    ("cat ./.claude/daedalus/reply-hmac.key | head", "credential_read"),
    ("echo x > .claude/daedalus/audit/s.jsonl", "protected_folder_write"),
    ("cd .claude && echo x > daedalus/train.active", "protected_folder_write"),
    ("echo x | tee .claude/daedalus/state.json", "protected_folder_write"),
    ("echo x | tee $CLAUDE_PLUGIN_DATA/state.json", "protected_folder_write"),
    (f"{DEL} ./.claude/daedalus/audit", "protected_folder_write"),
    ("GIT_DIR=.claude/daedalus git add x", "protected_folder_write"),
    ("git push --force origin feature/x", "push_or_merge"),
    ("{git,} push origin feature/x", "push_or_merge"),
    ('"$g" push origin feature/x', "push_or_merge"),
    ("find . -name x -exec git push origin y ;", "push_or_merge"),
    ("env -S 'git push origin feature/x'", "push_or_merge"),
    ("bash -c 'git push origin feature/x'", "push_or_merge"),
    ("eval git push origin feature/x", "push_or_merge"),
    ("bash <<'E'\ngit push origin feature/x\nE", "push_or_merge"),
    ("sh <<< 'git push origin feature/x'", "push_or_merge"),
    ("git rebase -x 'git push origin feature/x' main", "push_or_merge"),
    ("echo push | xargs git", "push_or_merge"),
    ("f() { git push origin feature/x; }; f", "push_or_merge"),
    ("git merge daedalus/20261015-120000", "push_or_merge"),
    ("git p$X origin feature/x", "push_or_merge"),
    ("gh pr merge 5", "push_or_merge"),
    ("cd x && gh pr merge 5", "push_or_merge"),
    ("git -c alias.p=push p", "git_config_key"),
    # 0277: a gh call that pushes or merges by another route keeps the push note.
    ("gh api -X PUT repos/o/r/pulls/5/merge", "push_or_merge"),
    ("gh api -X PATCH repos/o/r/git/refs/heads/x -f sha=y", "push_or_merge"),
    ("gh api -X DELETE repos/o/r/git/refs/heads/x", "push_or_merge"),
    ("gh api -X PUT repos/o/r/contents/a.md -f message=x", "push_or_merge"),
    (
        "gh api graphql -f query='mutation { createCommitOnBranch(input: {}) { x } }'",
        "push_or_merge",
    ),
    ("gh api graphql --input q.json", "push_or_merge"),
    ("gh pr close 5 --delete-branch", "push_or_merge"),
    ("gh repo create x --source . --push", "push_or_merge"),
    ("gh repo sync o/fork", "push_or_merge"),
    ("gh co 5", "push_or_merge"),
    ("gh extension exec x", "push_or_merge"),
    ('gh "$c" merge 5', "push_or_merge"),
    ("gh pr merge -sd 5", "push_or_merge"),
)


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize(("command", "klass"), HUNT)
def test_a_hunt_form_off_mains_grammar_is_still_noted(
    cred_home: Path, plugin_data: Path, command: str, klass: str
) -> None:
    (cred_home / ".ssh").mkdir()
    (cred_home / ".aws").mkdir()
    d = decide(_b(None, command), CFG)
    assert d.warn and d.note == klass, (command, d)
    assert "refused" not in str(d.reason).casefold(), d.reason


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize(
    "command",
    [
        "git log --oneline | head -5",
        "ls ~/notes",
        "echo {} done",
        "find . -name '*.py' -exec wc -l {} +",
        "python3 $CLAUDE_PLUGIN_ROOT/scripts/verify_audit_chain.py .claude/daedalus/audit/a",
        "git pull --ff-only",
    ],
)
def test_ordinary_work_off_mains_grammar_runs_with_no_note(command: str) -> None:
    d = decide(_b(None, command), CFG)
    assert d.allow and not d.warn and d.note is None, (command, d)


def test_a_push_in_the_release_phase_runs_with_no_note(
    marked_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _cred(None, "Bash", str(marked_repo), command="git push -u origin feature/x")
    assert decide(payload, CFG).note == "push_or_merge"
    phases: dict[str, object] = {train_state.PHASE: "release"}
    monkeypatch.setattr(train_state, "load", lambda *_args: phases)
    d = decide(payload, CFG)
    assert d.allow and not d.warn, d
    phases[train_state.PHASE] = "build"
    assert decide(payload, CFG).note == "push_or_merge"


def test_the_release_check_reads_only_the_active_runs_phase(tmp_path: Path) -> None:
    check: Callable[[], bool] = jail._release_check(str(tmp_path))
    assert check() is False
    assert jail._release_check("relative")() is False


def test_the_excluded_reading_finds_a_case_trick_off_mains_grammar(tmp_path: Path) -> None:
    repo = tmp_path.resolve()
    (repo / ".git").mkdir()
    roots = (config.ExcludedRoot(str(repo / "notes")),)
    for command in (
        "export GIT_ICASE_PATHSPECS=1; git add NOTES/a.md",
        "env GIT_ICASE_PATHSPECS=1 git add NOTES/a.md",
        "git add ':(icase)NOTES/a.md' $(true)",
        "bash -c 'git add notes/a.md'",
    ):
        found = session_reading.excluded_reason(command, str(repo), lambda: roots)
        assert found is not None, command
    assert (
        session_reading.excluded_reason("git add src/a.md $(true)", str(repo), lambda: roots)
        is None
    )


# 0277: the thirteen session notes; these names are the whole table, in its order.
THIRTEEN = (
    "credential_read",
    "protected_folder_write",
    "push_or_merge",
    "credential_write",
    "git_metadata_write",
    "main_checkout_write",
    "dispatch_rule",
    "resume_rule",
    "excluded_folder",
    "excluded_folder_unchecked",
    "signing",
    "git_config_key",
    "destructive_delete",
)
_ISSUE_NEW = "gh issue " + "create"
# 0277: forms of the four dropped classes and gh writes that are neither a push nor a merge.
DROPPED = (
    "gh pr create --title x --body y",
    f"{_ISSUE_NEW} --title x --body y",
    f'{_ISSUE_NEW} --title x --body "$B"',
    "gh release create v1",
    "gh alias set co 'pr merge'",
    "gh api -f title=x repos/o/r/issues",
    "gh api -X PATCH repos/o/r",
    "claude -p hi",
    "timeout 5 claude -p hi",
    "bash -c 'claude -p hi'",
    "PATH=/x git status",
    "export PATH=/x:/y; git log",
    "LD_PRELOAD=/x.so git status",
)


def test_the_table_holds_exactly_the_thirteen_session_notes() -> None:
    assert tuple(k.name for k in notes.NOTE_CLASSES) == THIRTEEN
    dropped = ("NESTED_SESSION", "GITHUB_CHANGE", "LOOKUP_VARIABLE", "NO_WORKING_FOLDER")
    assert not any(hasattr(notes, name) for name in dropped)


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize("command", DROPPED)
def test_a_dropped_class_form_runs_with_no_note(command: str) -> None:
    d = decide(_b(None, command), CFG)
    assert d.allow and not d.warn and d.reason is None and d.note is None, (command, d)


@pytest.mark.parametrize(
    "command",
    [
        "gh pr create --title x --body y",
        f"{_ISSUE_NEW} --title x",
        "claude -p hi",
        "PATH=/x git status",
    ],
)
def test_a_dropped_class_form_records_allow_with_no_reason(
    run_script: Any, project_data: Path, hook_input: Any, command: str
) -> None:
    write_train_marker(project_data.parent.parent)
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": command}))
    assert (result.returncode, result.stdout, result.stderr) == (0, "", ""), result
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and rec["reason"] is None, rec


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize("cwd", ["", "relative/repo"])
def test_a_call_with_no_working_folder_runs_with_no_note(cwd: str, cred_home: Path) -> None:
    for payload in (_b(None, "git push origin x"), _w(None, f"{CWD}/.git/config")):
        d = decide({**payload, "cwd": cwd}, CFG)
        assert d.allow and not d.warn and d.note is None, (cwd, d)
    # 0277: the credential checks need no folder, so they still note an absolute store path.
    key = f"{cred_home}/.ssh/id_ed25519"
    d = decide({**_cred(None, "Read", file_path=key), "cwd": cwd}, CFG)
    assert d.note == "credential_read", d


def test_a_call_with_no_working_folder_gets_only_the_unrecorded_alert(
    run_script: Any, hook_input: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0277: no folder names no log to record in; the hook's own alert says so, never a note.
    monkeypatch.chdir(tmp_path)
    payload = hook_input(tool_input={"command": "git push origin x"}, cwd="")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0, result
    alert = main_warning(result.stdout)
    assert alert.startswith(enforce_agent_jail._AUDIT_WARN.format(tool="Bash")), alert
    assert not any(name in alert for name in THIRTEEN), alert
    assert not (tmp_path / ".claude").exists()


def _release_choice() -> list[str]:
    # 0277: the release skill's own step 7 command, read from the skill text.
    text = (Path(__file__).resolve().parents[1] / "skills" / "release" / "SKILL.md").read_text()
    step7 = text.split("\n7. ", 1)[1].split("\n8. ", 1)[0]
    found = re.search(
        r"`python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/daedalus_train\.py (choice [^`]+)`", step7
    )
    assert found is not None, step7
    return shlex.split(found.group(1))


@pytest.mark.usefixtures("jail_fakes")
@pytest.mark.parametrize("command", ["git push -u origin feature/x", "gh pr merge 5"])
def test_the_release_step_records_the_phase_and_silences_the_push_note(
    repo_cwd: Path, command: str
) -> None:
    seed_train(repo_cwd, train="20261016-120000")
    payload = _cred(None, "Bash", str(repo_cwd), command=command)
    assert decide(payload, CFG).note == "push_or_merge"
    args = _release_choice()
    assert args[args.index("--phase") + 1] == "release", args
    value = {k: args[args.index(f"--{k}") + 1] for k in ("chose", "over", "cost")}
    outcome = train_runner.choice(repo_cwd, phase="release", **value)
    assert outcome.code == train_runner.EXIT_OK, outcome
    assert train_state.load(repo_cwd, "20261016-120000")[train_state.PHASE] == "release"
    d = decide(payload, CFG)
    assert d.allow and not d.warn and d.note is None, d


def test_the_release_step_command_is_kept_in_the_audit_log(
    run_script: Any, repo_cwd: Path, project_data: Path, hook_input: Any
) -> None:
    # 0277: the phase is set by a main-session command, so the audit log keeps who set it.
    seed_train(repo_cwd, train="20261016-120000")
    command = "python3 /p/scripts/daedalus_train.py " + shlex.join(_release_choice())
    result = run_script("enforce_agent_jail.py", hook_input(tool_input={"command": command}))
    assert result.returncode == 0, result
    rec = audit_records(project_data / "audit" / "sess-test.jsonl")[-1]
    assert rec["decision"] == "allow" and "--phase release" in str(rec["tool_input"]), rec
