# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0136, D.2.1, D.5: the excluded_roots key, its resolution, the check and the main session warning.
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import enforce_agent_jail
import pytest
from lib import hook_io, jail, router
from lib.config import (
    Config,
    ConfigError,
    ExcludedRoot,
    ExcludedRootDecl,
    load_config,
    resolve_excluded_roots,
    root_ignored,
)

from tests.adversarial.corpus import H1_ICASE
from tests.conftest import git, main_warning, write_train_marker
from tests.hook_chain import load


@pytest.fixture
def repo(git_repo: Path) -> Path:
    # D.5: a repo whose private/ is ignored and whose notes/ is not.
    (git_repo / ".gitignore").write_text("private/\n", encoding="utf-8")
    for name in ("private", "notes", "src"):
        (git_repo / name).mkdir()
        (git_repo / name / "a.md").write_text("x\n", encoding="utf-8")
    (git_repo / ".claude" / "daedalus").mkdir(parents=True)
    return git_repo


def _write_config(repo: Path, roots: list[dict[str, str]]) -> None:
    data = repo / ".claude" / "daedalus" / "config.json"
    data.write_text(json.dumps({"excluded_roots": roots}), encoding="utf-8")


def _roots(*paths: str, ignored: bool | None = None) -> jail.ExcludedRoots:
    found = tuple(ExcludedRoot(p, ignored) for p in paths)
    return lambda: found


def test_excluded_roots_key_reads_paths_and_gitignore(repo: Path) -> None:
    roots = [{"kind": "path", "path": "<repo_root>/private/"}, {"kind": "gitignore"}]
    _write_config(repo, roots)
    config = load_config(str(repo))
    assert config.excluded_roots == (
        ExcludedRootDecl("path", "<repo_root>/private/"),
        ExcludedRootDecl("gitignore", None, "directories"),
    )
    assert load_config(str(repo)).excluded_roots[1].match == "directories"


@pytest.mark.parametrize(
    "value",
    [
        {"kind": "path"},
        [{"kind": "manifest", "key": "excluded_roots"}],
        [{"kind": "path", "path": ""}],
        [{"kind": "gitignore", "match": "files"}],
        ["private/"],
    ],
)
def test_excluded_roots_key_refuses_a_bad_entry(repo: Path, value: object) -> None:
    data = repo / ".claude" / "daedalus" / "config.json"
    data.write_text(json.dumps({"excluded_roots": value}), encoding="utf-8")
    with pytest.raises(ConfigError, match="Next:"):
        load_config(str(repo))


def test_path_roots_fill_placeholders_and_read_relative_from_the_root(tmp_path: Path) -> None:
    decls = (
        ExcludedRootDecl("path", "<repo_root>/private/"),
        ExcludedRootDecl("path", "notes"),
        ExcludedRootDecl("path", "<charter_root>/drafts"),
    )
    config = Config(charter_root=tmp_path / "charter", excluded_roots=decls)
    got = resolve_excluded_roots(config, tmp_path)
    want = [str(tmp_path / "private"), str(tmp_path / "notes"), str(tmp_path / "charter/drafts")]
    assert [r.path for r in got] == want
    assert all(r.ignored is None for r in got)
    with pytest.raises(ConfigError, match="charter_root"):
        resolve_excluded_roots(Config(excluded_roots=decls[2:]), tmp_path)


def test_gitignore_roots_skip_a_folder_holding_a_linked_worktree(repo: Path) -> None:
    (repo / ".gitignore").write_text("private/\nwork/\n*.log\n", encoding="utf-8")
    (repo / "run.log").write_text("x\n", encoding="utf-8")
    git(repo, "worktree", "add", "-q", str(repo / "work" / "u1"))
    decl = (ExcludedRootDecl("gitignore", None, "directories"),)
    got = resolve_excluded_roots(Config(excluded_roots=decl), repo)
    assert [r.path for r in got] == [str(repo / "private")]
    assert got[0].ignored is True
    every = resolve_excluded_roots(
        Config(excluded_roots=(ExcludedRootDecl("gitignore", None, "all"),)), repo
    )
    assert str(repo / "run.log") in [r.path for r in every]


def test_no_excluded_roots_block_resolves_to_none(repo: Path) -> None:
    assert resolve_excluded_roots(Config(), repo) == ()


def test_root_ignored_asks_git_check_ignore(repo: Path) -> None:
    assert root_ignored(ExcludedRoot(str(repo / "private")), repo) is True
    assert root_ignored(ExcludedRoot(str(repo / "notes")), repo) is False
    assert root_ignored(ExcludedRoot(str(repo.parent / "elsewhere")), repo) is False


@pytest.mark.parametrize(
    "command",
    [
        "git add private/a.md",
        "git -C private add a.md",
        "git stage ./private/a.md",
        "git add -f private",
        "git commit -m fix private/a.md",
        "git commit -F private/a.md",
        "git update-index --add private/a.md",
        "git stash push -- private/a.md",
        "git add ':(top)private/a.md'",
        "cd {repo} && git add private/a.md",
        "gh pr create --title t --body-file private/a.md",
        "gh api repos/o/r/issues -F body=@private/a.md",
        "echo x > private/out.md",
        "cat src/a.md | tee -a {repo}/private/out.md",
    ],
)
def test_a_command_naming_a_path_under_a_root_is_refused(repo: Path, command: str) -> None:
    got = jail.excluded_root_reason(
        command.format(repo=repo), str(repo), _roots(str(repo / "private"))
    )
    assert got is not None and "excluded root" in got and str(repo / "private") in got, command


@pytest.mark.parametrize(
    "command",
    [
        "git add src/a.md",
        "git add ':!private'",
        "git commit -m 'notes on private/a.md'",
        "git stash list",
        "git stash save private/a.md",
        "git status",
        "gh pr view 3",
        "cat private/a.md",
        "echo x > src/out.md",
        "git add -A",
        "git commit -a -m m",
        "git add .",
    ],
)
def test_other_commands_pass_an_ignored_root(repo: Path, command: str) -> None:
    roots = _roots(str(repo / "private"), ignored=True)
    assert jail.excluded_root_reason(command, str(repo), roots) is None, command


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git add --all",
        "git add .",
        "git commit -am m",
        "git stash -u",
        "git add 'no*'",
    ],
)
def test_a_whole_tree_command_refuses_a_root_git_does_not_ignore(repo: Path, command: str) -> None:
    got = jail.excluded_root_reason(command, str(repo), _roots(str(repo / "notes")))
    assert got == jail.R_EXCLUDED_TREE.format(what=f"git {command.split()[1]}", root=repo / "notes")


@pytest.mark.parametrize("command", ["git add -A -f", "git stash --all", "git add -f ."])
def test_a_forced_whole_tree_command_refuses_an_ignored_root(repo: Path, command: str) -> None:
    roots = _roots(str(repo / "private"), ignored=True)
    assert jail.excluded_root_reason(command, str(repo), roots) is not None, command


def test_a_repository_inside_a_root_is_its_own_repo(repo: Path) -> None:
    # D.5: a nested clone under an excluded root commits to itself, never to the outer repo.
    nested = repo / "private" / "clone"
    nested.mkdir()
    git(nested, "init", "-q", "-b", "main")
    roots = _roots(str(repo / "private"))
    assert jail.excluded_root_reason(f"git -C {nested} add -A", str(repo), roots) is None
    assert jail.excluded_root_reason("git add a.md", str(nested), roots) is None
    assert jail.excluded_root_reason(f"git add {nested}/a.md", str(repo), roots) is not None


def test_a_linked_worktree_meets_each_root_at_its_own_path(repo: Path) -> None:
    tree = repo / ".claude" / "worktrees" / "u1"
    git(repo, "worktree", "add", "-q", str(tree))
    (tree / "notes").mkdir(exist_ok=True)
    roots = _roots(str(repo / "notes"))
    got = jail.excluded_root_reason(f"git -C {tree} add notes/a.md", str(repo), roots)
    assert got is not None and str(tree / "notes") in got


def test_redirects_pass_for_the_document_writers(repo: Path) -> None:
    roots = _roots(str(repo / "private"))
    assert jail.excluded_root_reason("echo x > private/o.md", str(repo), roots, False) is None
    assert jail.excluded_root_reason("git add private/o.md", str(repo), roots, False) is not None


def test_an_unparsed_command_is_judged_on_its_text(repo: Path) -> None:
    roots = _roots(str(repo / "private"))
    got = jail.excluded_root_reason("git add $(ls private)", str(repo), roots)
    assert got == jail.R_EXCLUDED_TEXT.format(root=repo / "private")
    assert jail.excluded_root_reason("ls $(pwd)", str(repo), roots) is None


def test_roots_resolve_only_when_a_command_reaches_git_gh_or_a_redirect(repo: Path) -> None:
    calls: list[int] = []

    def roots() -> tuple[ExcludedRoot, ...]:
        calls.append(1)
        return ()

    assert jail.excluded_root_reason("ls -la && cat src/a.md", str(repo), roots) is None
    assert calls == []


def _payload(agent: str, cwd: Path, command: str) -> dict[str, object]:
    return {
        "agent_type": agent,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def _config(repo: Path) -> Config:
    return Config(excluded_roots=(ExcludedRootDecl("path", str(repo / "notes")),))


def test_check_refuses_staging_an_excluded_root(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: _config(repo))
    check = load("excluded_roots")
    got = check.decide(_payload("daedalus:repo-coder", repo, "git add notes/a.md"), [])
    assert not got.allow and str(repo / "notes") in str(got.reason)
    assert check.decide(_payload("daedalus:repo-coder", repo, "git add src/a.md"), []).allow
    writer = _payload("daedalus:doc-deriver", repo, "echo x > notes/b.md")
    assert check.decide(writer, []).allow
    assert not check.decide(_payload("daedalus:repo-coder", repo, "echo x > notes/b.md"), []).allow


def test_check_refuses_without_an_absolute_cwd() -> None:
    got = load("excluded_roots").decide(_payload("daedalus:repo-coder", Path("rel"), "ls"), [])
    assert got.reason == jail.R_NO_CWD


def test_router_runs_the_check_for_every_routed_agent(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0136: an agent whose own hooks allow everything still meets the excluded roots check.
    monkeypatch.setattr(router, "_MODULES", {})
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: _config(repo))
    plugin = tmp_path / "plugin"
    (plugin / "agents").mkdir(parents=True)
    (plugin / "scripts" / "checks").mkdir(parents=True)
    script = "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py"
    hook = '        - {type: command, command: "' + script + '"}'
    lines = ["---", "name: probe", "description: probe agent", "tools: Bash", "model: haiku"]
    lines += ["shape: finder", "hooks:", "  PreToolUse:", "    - hooks:", hook, "---", "body", ""]
    (plugin / "agents" / "probe.md").write_text("\n".join(lines), encoding="utf-8")
    opener = "from lib import hook_io\n\n\ndef decide(i, f):\n"
    opener += "    return hook_io.HookDecision(True, None)\n"
    (plugin / "scripts" / "checks" / "tool_bound.py").write_text(opener, encoding="utf-8")
    allow, reason, name = router.route(_payload("probe", repo, "git add notes/a.md"), plugin)
    assert (allow, name) == (False, "excluded_roots"), reason
    assert str(repo / "notes") in str(reason)
    assert router.route(_payload("probe", repo, "git add src/a.md"), plugin) == (True, None, "")


def test_main_session_is_warned_and_never_refused(repo: Path) -> None:
    # 0130: lib.jail allows with context for the operator's own session whenever it is called.
    payload = _payload("main", repo, "git add notes/a.md")
    got = jail.decide(payload, _config(repo))
    assert got.warn and not got.allow and got.reason is not None
    assert got.reason.startswith(jail.WARN_EXCLUDED) and str(repo / "notes") in got.reason
    assert jail.decide(_payload("main", repo, "git add src/a.md"), _config(repo)).allow
    write_train_marker(repo)
    assert jail.decide(payload, _config(repo)).warn


def _hook(
    repo: Path, command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str]:
    payload = _payload("main", repo, command) | {
        "session_id": "sess-test",
        "hook_event_name": "PreToolUse",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    code = enforce_agent_jail.main()
    return code, capsys.readouterr().out


def test_hook_warns_the_main_session_during_a_train(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0130, D.5: the PreToolUse entry gives main the warning in context for a marked repo.
    _write_config(repo, [{"kind": "path", "path": "<repo_root>/notes"}])
    write_train_marker(repo)
    code, out = _hook(repo, "git add notes/a.md", monkeypatch, capsys)
    assert code == 0
    warning = main_warning(out)
    assert warning.startswith(jail.WARN_EXCLUDED) and str(repo / "notes") in warning
    assert _hook(repo, "git add src/a.md", monkeypatch, capsys) == (0, "")


def test_hook_gives_no_warning_outside_a_train(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0035: outside a train the hook steps aside for main, so no excluded roots warning appears.
    _write_config(repo, [{"kind": "path", "path": "<repo_root>/notes"}])
    assert _hook(repo, "git add notes/a.md", monkeypatch, capsys) == (0, "")


@pytest.mark.parametrize("command", H1_ICASE)
def test_an_icase_pathspec_is_refused_while_a_root_is_declared(repo: Path, command: str) -> None:
    # issue 97: git would match notes/a.md in any case; the spelled path never names the root.
    got = jail.excluded_root_reason(command, str(repo), _roots(str(repo / "notes")))
    assert got is not None and got.startswith(jail.R_EXCLUDED_ICASE.split("{spec}")[0]), command
    assert "Next: spell each path in its exact case" in got
    assert jail.excluded_root_reason(command, str(repo), _roots()) is None, command


@pytest.mark.parametrize("command", H1_ICASE)
def test_check_refuses_an_icase_pathspec(
    repo: Path, command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # issue 97: judge in checks/excluded_roots.py meets the shared rule for every routed agent.
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: _config(repo))
    got = load("excluded_roots").decide(_payload("daedalus:repo-coder", repo, command), [])
    assert not got.allow and "letter case" in str(got.reason), command


@pytest.mark.parametrize(
    ("spec", "icase"),
    [
        (":(icase)a", True),
        (":(top, icase)a", True),
        (":(icase", True),
        (":i:a", True),
        (":/I:a", True),
        (":(top)a", False),
        (":(icasefold)a", False),
        (":/:a", False),
        (":!a", False),
        (":/icase-dir/a", False),
        ("icase", False),
    ],
)
def test_icase_spec_reads_the_long_and_short_magic(spec: str, icase: bool) -> None:
    assert jail._icase_spec(spec) is icase


def test_case_exact_pathspecs_and_reads_still_pass(repo: Path) -> None:
    # issue 97: an exact-case pathspec outside the root, and a message naming icase, pass.
    roots = _roots(str(repo / "notes"))
    for command in ("git add ':(top)src/a.md'", "git commit -m ':(icase) note'", "git status"):
        assert jail.excluded_root_reason(command, str(repo), roots) is None, command


def test_main_session_is_warned_when_roots_cannot_resolve(repo: Path) -> None:
    config = Config(excluded_roots=(ExcludedRootDecl("path", "<charter_root>/x"),))
    got = jail.decide(_payload("main", repo, "git add notes/a.md"), config)
    assert got.warn and str(got.reason).startswith(jail.WARN_EXCLUDED_FAILED)
