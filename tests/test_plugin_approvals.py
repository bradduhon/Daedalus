# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import enforce_agent_jail
import pytest
from lib import plugin_approvals, self_assessment, storage
from lib import session_notes as notes

from tests.conftest import SCRIPTS_DIR, write_train_marker

STAMP = "20261110T120000Z"
Outcome = tuple[int, str, str]


@pytest.fixture
def plugin_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Spec 8: a stub findings script under a temporary plugin root the hook is told about.
    root = tmp_path.resolve() / "plugin"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "daedalus_findings.py").write_text("# stub\n", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    return root


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plugin_data: Path) -> Path:
    folder = tmp_path.resolve() / "home"
    (folder / ".claude" / "daedalus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.setattr(storage, "TMP_ROOT", tmp_path.resolve() / "tmproot")
    return folder


@pytest.fixture
def env(plugin_root: Path, home: Path, repo_cwd: Path) -> Path:
    return repo_cwd


def _mode(home: Path, on: bool) -> None:
    path = home / ".claude" / "daedalus" / "operator.json"
    path.write_text(json.dumps({"self_assessment": on}), encoding="utf-8")


def _script(root: Path) -> str:
    return str(root / "scripts" / "daedalus_findings.py")


def _calls(root: Path, repo: Path) -> dict[str, str]:
    script = _script(root)
    return {
        "findings-start": f"python3 {script} start --repo {repo}",
        "findings-save": f"python3 {script} save --repo {repo} --since {STAMP}",
        "findings-show": f"python3 {script} show --repo {repo} --since {STAMP}",
    }


def _bash(repo: Path, command: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": "sess-test",
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "findings"},
        "tool_use_id": "toolu_1",
    }
    payload.update(extra)
    return payload


def _write(repo: Path, path: Path | str, content: str = "{}", **extra: Any) -> dict[str, Any]:
    payload = _bash(repo, "")
    payload["tool_name"] = "Write"
    payload["tool_input"] = {"file_path": str(path), "content": content}
    payload.update(extra)
    return payload


def _handover(repo: Path) -> Path:
    return self_assessment.make_handover_dir(repo) / self_assessment.handover_name(STAMP)


def _allow(row: str) -> str:
    out = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": f"Daedalus approval list: {row} (0253)",
    }
    return json.dumps({"hookSpecificOutput": out}) + "\n"


@pytest.fixture
def hook(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Callable[[dict[str, Any], bool], Outcome]:
    # The hook in process, with the approval list live or replaced by a no-approval stub.
    def _run(payload: dict[str, Any], approvals: bool = True) -> Outcome:
        with monkeypatch.context() as patch:
            if not approvals:
                patch.setattr(plugin_approvals, "approve", lambda _payload: None)
            patch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
            code = enforce_agent_jail.main()
        got = capsys.readouterr()
        return code, got.out, got.err

    return _run


@pytest.fixture
def same_as_today(
    hook: Callable[[dict[str, Any], bool], Outcome],
) -> Callable[[dict[str, Any]], Outcome]:
    # A3 req 7: with no row matched, output and exit code equal the hook with no approval list.
    def _check(payload: dict[str, Any]) -> Outcome:
        today = hook(payload, False)
        now = hook(payload, True)
        assert now == today
        assert "permissionDecision" not in now[1]
        return now

    return _check


# -- each row's approval -------------------------------------------------------------------------


def test_the_table_holds_exactly_four_rows() -> None:
    names = [row.name for row in plugin_approvals.APPROVALS]
    assert names == ["findings-start", "findings-save", "findings-show", "handover-write"]


@pytest.mark.parametrize("on", [True, False])
@pytest.mark.parametrize("row", ["findings-start", "findings-save", "findings-show"])
def test_each_script_row_is_approved_mode_on_or_off(
    env: Path, plugin_root: Path, home: Path, hook: Any, row: str, on: bool
) -> None:
    _mode(home, on)
    payload = _bash(env, _calls(plugin_root, env)[row])
    assert plugin_approvals.approve(payload) == row
    assert hook(payload, False) == (0, "", "")
    assert hook(payload) == (0, _allow(row), "")


@pytest.mark.parametrize("row", ["findings-start", "findings-save", "findings-show"])
def test_each_script_row_is_approved_during_a_run(
    env: Path, plugin_root: Path, hook: Any, row: str
) -> None:
    write_train_marker(env)
    payload = _bash(env, _calls(plugin_root, env)[row])
    assert hook(payload, False) == (0, "", "")
    assert hook(payload) == (0, _allow(row), "")


def test_the_script_rows_take_a_quoted_path_word(env: Path, plugin_root: Path) -> None:
    command = f"python3 {_script(plugin_root)} start --repo '{env}'"
    assert plugin_approvals.approve(_bash(env, command)) == "findings-start"


def test_the_handover_write_is_approved_with_the_mode_on(env: Path, home: Path, hook: Any) -> None:
    _mode(home, True)
    payload = _write(env, _handover(env), "x" * self_assessment.MAX_HANDOVER_BYTES)
    assert plugin_approvals.approve(payload) == "handover-write"
    assert hook(payload, False) == (0, "", "")
    assert hook(payload) == (0, _allow("handover-write"), "")


def test_the_handover_write_is_approved_during_a_run(env: Path, home: Path, hook: Any) -> None:
    _mode(home, True)
    write_train_marker(env)
    payload = _write(env, _handover(env))
    assert hook(payload, False) == (0, "", "")
    assert hook(payload) == (0, _allow("handover-write"), "")


def test_the_handover_write_over_an_existing_plain_file_is_approved(env: Path, home: Path) -> None:
    _mode(home, True)
    target = _handover(env)
    target.write_text("{}", encoding="utf-8")
    assert plugin_approvals.approve(_write(env, target)) == "handover-write"


def test_the_handover_write_from_a_subfolder_names_the_projects_folder(
    env: Path, home: Path
) -> None:
    _mode(home, True)
    sub = env / "src" / "deep"
    sub.mkdir(parents=True)
    assert plugin_approvals.approve(_write(sub, _handover(env))) == "handover-write"


def test_the_real_hook_approves_a_start_call(env: Path, plugin_root: Path) -> None:
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    done = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "enforce_agent_jail.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=dict(os.environ),
        check=False,
    )
    assert (done.returncode, done.stdout, done.stderr) == (0, _allow("findings-start"), "")


# -- the script rows: near-misses keep today's outcome ------------------------------------------


def _variants(root: Path, repo: Path, other: Path) -> list[tuple[str, str]]:
    script = _script(root)
    start = f"python3 {script} start --repo {repo}"
    save = f"python3 {script} save --repo {repo} --since {STAMP}"
    show = f"python3 {script} show --repo {repo} --since {STAMP}"
    out: list[tuple[str, str]] = []
    for base in (start, save, show):
        out += [
            ("semicolon", f"{base}; true"),
            ("and list", f"{base} && true"),
            ("or list", f"true || {base}"),
            ("pipe", f"{base} | cat"),
            ("pipe into", f"echo x | {base}"),
            ("newline", f"{base}\ntrue"),
            ("trailing separator", f"{base};"),
            ("background", f"{base} &"),
            ("redirection", f"{base} > {repo}/out.txt"),
            ("stderr redirection", f"{base} 2>&1"),
            ("input redirection", f"{base} < /dev/null"),
            ("assignment", f"X=1 {base}"),
            ("path substitution", base.replace(f"--repo {repo}", "--repo $(pwd)")),
            ("backtick substitution", base.replace(f"--repo {repo}", "--repo `pwd`")),
            ("path variable", base.replace(f"--repo {repo}", '--repo "$PWD"')),
            ("path tilde", base.replace(f"--repo {repo}", "--repo ~/x")),
            ("path glob", base.replace(f"--repo {repo}", f"--repo {repo}*")),
            ("python", base.replace("python3 ", "python ", 1)),
            ("python3 by path", base.replace("python3 ", "/usr/bin/python3 ", 1)),
            ("quoted python3", base.replace("python3 ", "'python3' ", 1)),
            ("escaped python3", base.replace("python3 ", "pyth\\on3 ", 1)),
            ("script variable", base.replace(script, "${CLAUDE_PLUGIN_ROOT}/scripts/x.py")),
            ("dot dot", base.replace(script, f"{root}/scripts/../scripts/daedalus_findings.py")),
            ("double slash", base.replace(script, f"{root}//scripts/daedalus_findings.py")),
            ("other root", base.replace(script, _script(other))),
            ("relative script", base.replace(script, "scripts/daedalus_findings.py")),
            ("extra option", f"{base} --force"),
            ("extra word", f"{base} x"),
            ("repeated repo", base.replace(f"--repo {repo}", f"--repo {repo} --repo {repo}")),
            ("missing repo", base.replace(f" --repo {repo}", "")),
            ("repo with equals", base.replace(f"--repo {repo}", f"--repo={repo}")),
            ("quoted option", base.replace("--repo", "'--repo'")),
            ("option path", base.replace(f"--repo {repo}", "--repo --x")),
            ("empty path", base.replace(f"--repo {repo}", "--repo ''")),
            ("negated", f"! {base}"),
            ("timed", f"time {base}"),
            ("subshell", f"({base})"),
            ("group", f"{{ {base}; }}"),
            ("comment", f"{base} # note"),
            ("leading double dash", base.replace("python3 ", "python3 -- ", 1)),
            ("python option", base.replace("python3 ", "python3 -I ", 1)),
            ("line continuation", base.replace(" --repo", " \\\n--repo")),
        ]
    for sub in ("save", "show"):
        base = save if sub == "save" else show
        out += [
            ("missing since", base.replace(f" --since {STAMP}", "")),
            ("repeated since", f"{base} --since {STAMP}"),
            ("since with equals", base.replace(f"--since {STAMP}", f"--since={STAMP}")),
            ("bad stamp", base.replace(STAMP, "20261110T1200Z")),
            ("lowercase stamp", base.replace(STAMP, STAMP.lower())),
            ("quoted stamp", base.replace(STAMP, f"'{STAMP}'")),
            ("stamp substitution", base.replace(STAMP, "$(date)")),
            ("swapped options", f"python3 {script} {sub} --since {STAMP} --repo {repo}"),
        ]
    out += [
        ("start with since", f"{start} --since {STAMP}"),
        ("unknown subcommand", start.replace(" start ", " purge ")),
    ]
    return out


@pytest.fixture
def other_root(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "other-plugin"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "daedalus_findings.py").write_text("# stub\n", encoding="utf-8")
    return root


def test_every_script_near_miss_keeps_todays_outcome(
    env: Path, plugin_root: Path, home: Path, other_root: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    for label, command in _variants(plugin_root, env, other_root):
        assert plugin_approvals.approve(_bash(env, command)) is None, label
        same_as_today(_bash(env, command))


def test_every_script_near_miss_keeps_todays_outcome_during_a_run(
    env: Path, plugin_root: Path, home: Path, other_root: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    write_train_marker(env)
    for label, command in _variants(plugin_root, env, other_root):
        assert plugin_approvals.approve(_bash(env, command)) is None, label
        same_as_today(_bash(env, command))


def test_a_symlink_to_the_script_is_not_approved(
    env: Path, plugin_root: Path, tmp_path: Path, same_as_today: Any
) -> None:
    link = tmp_path / "link.py"
    link.symlink_to(_script(plugin_root))
    same_as_today(_bash(env, f"python3 {link} start --repo {env}"))


def test_a_script_that_is_itself_a_symlink_is_not_approved(
    env: Path, plugin_root: Path, other_root: Path, same_as_today: Any
) -> None:
    script = Path(_script(plugin_root))
    script.unlink()
    script.symlink_to(_script(other_root))
    same_as_today(_bash(env, _calls(plugin_root, env)["findings-start"]))


def test_a_scripts_folder_linked_out_of_the_root_is_not_approved(
    env: Path, plugin_root: Path, other_root: Path, same_as_today: Any
) -> None:
    (plugin_root / "scripts" / "daedalus_findings.py").unlink()
    (plugin_root / "scripts").rmdir()
    (plugin_root / "scripts").symlink_to(other_root / "scripts")
    same_as_today(_bash(env, _calls(plugin_root, env)["findings-start"]))


def test_a_missing_script_is_not_approved(env: Path, plugin_root: Path, same_as_today: Any) -> None:
    (plugin_root / "scripts" / "daedalus_findings.py").unlink()
    same_as_today(_bash(env, _calls(plugin_root, env)["findings-start"]))


@pytest.mark.parametrize("root", [None, "", "relative/plugin", "/a/../b"])
def test_no_usable_plugin_root_is_no_approval(
    env: Path,
    plugin_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    same_as_today: Any,
    root: str | None,
) -> None:
    command = _calls(plugin_root, env)["findings-start"]
    if root is None:
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT")
    else:
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", root)
    same_as_today(_bash(env, command))


@pytest.mark.parametrize(
    "extra",
    [
        {"run_in_background": True},
        {"dangerouslyDisableSandbox": True},
        {"run_in_background": "false"},
        {"unknown": 1},
    ],
)
def test_bash_input_keys_off_the_list_are_no_approval(
    env: Path, plugin_root: Path, same_as_today: Any, extra: dict[str, Any]
) -> None:
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    payload["tool_input"].update(extra)
    same_as_today(payload)


def test_bash_flag_keys_set_false_still_approve(env: Path, plugin_root: Path) -> None:
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    payload["tool_input"].update({"run_in_background": False, "timeout": 5000})
    assert plugin_approvals.approve(payload) == "findings-start"


@pytest.mark.parametrize(
    "caller",
    [
        {"agent_id": "a1", "agent_type": "general-purpose"},
        {"agent_id": "a1"},
        {"agent_type": "Explore"},
        {"agent_id": "a1", "agent_type": "daedalus:coder"},
    ],
)
def test_a_helper_caller_is_never_approved(
    env: Path, plugin_root: Path, home: Path, hook: Any, caller: dict[str, str]
) -> None:
    _mode(home, True)
    for payload in (
        _bash(env, _calls(plugin_root, env)["findings-start"], **caller),
        _write(env, _handover(env), **caller),
    ):
        assert plugin_approvals.approve(payload) is None
        assert "permissionDecision" not in hook(payload)[1]
        assert hook(payload) == hook(payload, False)


def test_no_cwd_is_no_approval(env: Path, plugin_root: Path, same_as_today: Any) -> None:
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    del payload["cwd"]
    assert plugin_approvals.approve(payload) is None
    same_as_today(payload)


# -- the hand-over write: near-misses keep today's outcome ---------------------------------------


def test_an_edit_to_the_handover_path_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    target.write_text("{}", encoding="utf-8")
    payload = _write(env, target)
    payload["tool_name"] = "Edit"
    payload["tool_input"] = {"file_path": str(target), "old_string": "{}", "new_string": "[]"}
    same_as_today(payload)


@pytest.mark.parametrize(
    "name",
    [
        f"handover-{STAMP}.json.bak",
        f"handover-{STAMP}.JSON",
        "handover-20261110T1200Z.json",
        f"other-{STAMP}.json",
        f"xhandover-{STAMP}.json",
        "handover.json",
    ],
)
def test_a_write_to_a_sibling_name_is_not_approved(
    env: Path, home: Path, same_as_today: Any, name: str
) -> None:
    _mode(home, True)
    same_as_today(_write(env, _handover(env).parent / name))


def test_content_one_byte_over_the_limit_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    same_as_today(_write(env, _handover(env), "x" * (self_assessment.MAX_HANDOVER_BYTES + 1)))
    # A multibyte character counts its bytes, not one.
    same_as_today(_write(env, _handover(env), "é" * (self_assessment.MAX_HANDOVER_BYTES // 2 + 1)))


def test_the_handover_write_with_the_mode_off_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, False)
    same_as_today(_write(env, _handover(env)))


def test_the_handover_write_with_no_personal_file_is_not_approved(
    env: Path, same_as_today: Any
) -> None:
    same_as_today(_write(env, _handover(env)))


@pytest.mark.parametrize("how", ["dangling link", "folder", "bad json", "bad value"])
def test_the_handover_write_with_an_unreadable_flag_is_not_approved(
    env: Path, home: Path, same_as_today: Any, how: str
) -> None:
    path = home / ".claude" / "daedalus" / "operator.json"
    if how == "dangling link":
        path.symlink_to(home / "missing.json")
    elif how == "folder":
        path.mkdir()
    else:
        path.write_text("{not json" if how == "bad json" else '{"self_assessment": "yes"}')
    same_as_today(_write(env, _handover(env)))


def test_a_project_override_turning_the_mode_off_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    (env / ".claude" / "daedalus").mkdir(parents=True)
    (env / ".claude" / "daedalus" / "config.json").write_text(
        json.dumps({"personal_overrides": {"self_assessment": False}})
    )
    same_as_today(_write(env, _handover(env)))


def test_another_projects_handover_folder_is_not_approved(
    env: Path, home: Path, other_repo: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    same_as_today(_write(env, _handover(other_repo)))


def test_a_symlinked_handover_folder_is_not_approved(
    env: Path, home: Path, tmp_path: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    target.parent.rmdir()
    target.parent.symlink_to(real)
    same_as_today(_write(env, target))


def test_a_folder_others_can_write_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    target.parent.parent.chmod(0o777)
    same_as_today(_write(env, target))


def test_a_symlinked_tmp_root_is_not_approved(
    env: Path, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    link = tmp_path / "tmplink"
    link.symlink_to(storage.TMP_ROOT)
    monkeypatch.setattr(storage, "TMP_ROOT", link)
    same_as_today(_write(env, self_assessment.handover_dir(env) / target.name))


def test_any_folder_check_refusal_is_not_approved(
    env: Path, home: Path, monkeypatch: pytest.MonkeyPatch, same_as_today: Any
) -> None:
    # Every reason check_dirs gives, a foreign owner of TMP_ROOT included, withholds the approval.
    _mode(home, True)
    target = _handover(env)
    monkeypatch.setattr(storage, "check_tmp_dirs", lambda *_: "belongs to another user")
    same_as_today(_write(env, target))


def test_a_tmp_root_that_is_a_file_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    storage.TMP_ROOT.write_text("", encoding="utf-8")
    target = self_assessment.handover_dir(env) / self_assessment.handover_name(STAMP)
    same_as_today(_write(env, target))


def test_a_symlinked_target_is_not_approved(
    env: Path, home: Path, tmp_path: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    target.symlink_to(tmp_path / "elsewhere.json")
    same_as_today(_write(env, target))


def test_a_hard_linked_target_is_not_approved(
    env: Path, home: Path, tmp_path: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    target.write_text("{}", encoding="utf-8")
    assert plugin_approvals.approve(_write(env, target)) == "handover-write"
    os.link(target, tmp_path / "second-name.json")
    assert plugin_approvals.approve(_write(env, target)) is None
    same_as_today(_write(env, target))


def test_a_target_that_is_a_folder_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    target.mkdir()
    same_as_today(_write(env, target))


def test_a_handover_folder_not_made_yet_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = self_assessment.handover_dir(env) / self_assessment.handover_name(STAMP)
    same_as_today(_write(env, target))


def test_a_handover_path_with_dot_dot_or_relative_is_not_approved(
    env: Path, home: Path, same_as_today: Any
) -> None:
    _mode(home, True)
    target = _handover(env)
    dotted = f"{target.parent}/../{target.parent.name}/{target.name}"
    same_as_today(_write(env, dotted))
    same_as_today(_write(env, target.name))
    same_as_today(_write(env, f"{target.parent}//{target.name}"))


@pytest.mark.parametrize(
    "tool_input",
    [
        {"content": "{}"},
        {"file_path": None, "content": "{}"},
        {"file_path": "TARGET"},
        {"file_path": "TARGET", "content": 1},
        {"file_path": "TARGET", "content": "{}", "extra": True},
    ],
)
def test_write_input_off_the_shape_is_not_approved(
    env: Path, home: Path, same_as_today: Any, tool_input: dict[str, Any]
) -> None:
    _mode(home, True)
    payload = _write(env, _handover(env))
    target = payload["tool_input"]["file_path"]
    payload["tool_input"] = {
        key: target if value == "TARGET" else value for key, value in tool_input.items()
    }
    same_as_today(payload)


# -- refusals, warnings and errors stay as they are ----------------------------------------------


def _credential_outcomes(hook: Any, main: dict[str, Any], row: str) -> None:
    # 0259: main gets the credential note and no decision; a helper is refused by name.
    assert plugin_approvals.approve(main) == row
    today = hook(main, False)
    assert hook(main) == today
    assert today[0] == 0 and "Warning: This " in today[1] and "a credential file" in today[1]
    assert "permissionDecision" not in today[1]
    helper = {**main, "agent_id": "a1", "agent_type": "general-purpose"}
    today = hook(helper, False)
    assert hook(helper) == today
    assert today[0] == 2 and "credential path" in today[2] and today[1] == ""


def test_a_credential_refusal_keeps_its_text_when_a_script_call_matches_a_row(
    env: Path, home: Path, hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The plugin root under ~/.aws makes the script word itself a credential path.
    root = home / ".aws" / "plugin"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "daedalus_findings.py").write_text("# stub\n", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    write_train_marker(env)
    _credential_outcomes(hook, _bash(env, _calls(root, env)["findings-start"]), "findings-start")


def test_a_credential_refusal_keeps_its_text_when_the_handover_write_matches_a_row(
    env: Path, home: Path, hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(storage, "TMP_ROOT", home / ".aws" / "tmproot")
    _mode(home, True)
    write_train_marker(env)
    _credential_outcomes(hook, _write(env, _handover(env)), "handover-write")


def test_a_warned_call_in_a_run_gets_no_approval(
    env: Path, plugin_root: Path, home: Path, hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A row-shaped call the run's rules warn about keeps the warning and gains no decision.
    from lib import jail

    write_train_marker(env)
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    warned = notes.note(notes.PUSH_OR_MERGE, "warned")
    monkeypatch.setattr(jail, "_main_bash", lambda command, cwd: jail._noted(warned))
    assert hook(payload) == hook(payload, False)
    code, out, _err = hook(payload)
    assert code == 0 and "warned" in out and "permissionDecision" not in out


def test_a_cwd_fallback_note_in_a_run_gets_no_approval(
    env: Path, plugin_root: Path, hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lib import audit

    write_train_marker(env)
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    real = audit.audit_append

    def _fell_back(*args: Any, **kwargs: Any) -> dict[str, object] | None:
        record = real(*args, **kwargs)
        return {**(record or {}), "root_source": "cwd-fallback"}

    monkeypatch.setattr(audit, "audit_append", _fell_back)
    code, out, err = hook(payload)
    assert code == 0 and out == "" and "fell back" in err


def test_an_error_inside_approve_keeps_todays_outcome(
    env: Path,
    plugin_root: Path,
    home: Path,
    hook: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mode(home, True)
    payloads = [_bash(env, _calls(plugin_root, env)["findings-start"]), _write(env, _handover(env))]

    def _boom(*_args: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(plugin_approvals.shparse, "parse", _boom)
    monkeypatch.setattr(self_assessment, "enabled", _boom)
    for payload in payloads:
        assert plugin_approvals.approve(payload) is None
        assert hook(payload) == (0, "", "")
    write_train_marker(env)
    for payload in payloads:
        assert hook(payload) == hook(payload, False)


def test_a_failed_approval_import_keeps_todays_outcome(
    env: Path, plugin_root: Path, hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _bash(env, _calls(plugin_root, env)["findings-start"])
    monkeypatch.setitem(sys.modules, "lib.plugin_approvals", None)
    assert hook(payload) == (0, "", "")
