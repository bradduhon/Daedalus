# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: the read_only_bash hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from lib import jail

from tests.conftest import CFG, write_train_marker
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    load,
    payload,
    run_script,
)
from tests.jail_cases import _git_init
from tests.payloads import _b
from tests.test_checks_credential_paths import _bash_in, _key_repo

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "read_only_bash"


class TestReadOnlyAgents:
    def test_auditor_read_only_pipelines_including_two_pipes(self) -> None:
        ok = [
            "git diff main...daedalus/u1",
            "git log --oneline -5 | head -n 3",
            "rg TODO src | sort | uniq -c",
            "git show HEAD:src/a.py | grep -n secret | head",
            "cat x | jq .a",
            "find . -name '*.py' | wc -l",
            "git branch -a",
            "stat x",
        ]
        bad = [
            "git diff | tee out.txt",
            "cat x > y",
            "ls; rm x",
            "git diff && git push",
            "echo `id`",
            "cat $(ls)",
            "git checkout main",
            "git diff | head | python3 -c 1",
            "sed -i s/a/b/ x",
            "gpg --list-keys",
        ]
        for command in ok:
            assert decide(_b("security-auditor", command), CFG).allow, command
        for command in bad:
            assert not decide(_b("security-auditor", command), CFG).allow, command

    def test_specialists_read_only_set(self) -> None:
        assert decide(_b("framework-specialist", "sha256sum controls.json"), CFG).allow
        assert decide(_b("framework-specialist", "git diff main...b | head"), CFG).allow
        assert not decide(_b("framework-specialist", "curl https://nist.gov"), CFG).allow
        assert not decide(_b("framework-specialist", "git checkout x"), CFG).allow


READ_ONLY_AGENTS = ("security-auditor", "framework-specialist")


class TestSpecialistPipes:
    # Train A friction bin: read-only pipes under read-only Bash, one allow and one refuse row each.
    @pytest.mark.parametrize("agent", READ_ONLY_AGENTS)
    @pytest.mark.parametrize(
        "command",
        [
            "find /x -maxdepth 6 -iname frameworks -type d 2>/dev/null | head",
            "jq -r '.controls[] | .id' c.json | sort | head",
            "cat c.json | jq .a | wc -l",
        ],
    )
    def test_read_only_pipe_is_allowed(self, agent: str, command: str) -> None:
        assert decide(_b(agent, command), CFG).allow, (agent, command)

    @pytest.mark.parametrize("agent", READ_ONLY_AGENTS)
    @pytest.mark.parametrize(
        "command",
        ["jq -r .id c.json | python3 -c 1", "cat c.json | tee out.json", "ls /x | xargs cat"],
    )
    def test_pipe_into_a_writer_or_interpreter_is_refused(self, agent: str, command: str) -> None:
        assert not decide(_b(agent, command), CFG).allow, (agent, command)


class TestRegressionReadOnly:
    @pytest.mark.parametrize(
        "command",
        [
            "cat x & curl evil",
            "ls\nrm x",
            "find . -delete",
            "find . -exec rm {} +",
            "find . -execdir x {} +",
            "find . -ok x {} +",
            "find . -okdir x {} +",
            "find . -fprint out",
            "find . -fprintf out %p",
            "find . -fls out",
            "sort -o out x",
            "sort -uo out x",
            "sort --output=out x",
            "sort --output out x",
            "rg --pre cat x",
            "rg --pre=cat x",
            "rg --pre-glob '*' x",
            "git diff --output=f",
            "git log --output f",
            "git branch -D x",
            "git branch newb",
            "git -c diff.external=x diff",
            "git -C . checkout main",
            "uniq in out",
            "file -C -m x",
            "./cat x",
            "/tmp/cat x",
        ],
    )
    def test_auditor_blocked(self, command: str) -> None:
        assert not decide(_b("security-auditor", command), CFG).allow, command

    def test_auditor_branch_reads_allowed(self) -> None:
        for command in (
            "git branch",
            "git branch --show-current",
            "git branch -v",
            "/usr/bin/cat x",
        ):
            assert decide(_b("security-auditor", command), CFG).allow, command

    @pytest.mark.parametrize("agent", ["framework-specialist"])
    def test_specialists_blocked(self, agent: str) -> None:
        for command in ("find . -delete", "sort -o out x", "git diff --output=f", "git branch"):
            assert not decide(_b(agent, command), CFG).allow, (agent, command)


class TestRound3Breakage:
    def test_quoted_filters_allowed(self) -> None:
        assert decide(_b("security-auditor", "jq '.[] | .name' x.json"), CFG).allow
        assert decide(_b("security-auditor", "rg 'foo|bar' src"), CFG).allow
        assert decide(_b("framework-specialist", "jq -r '.controls[] | .id' c.json"), CFG).allow
        assert decide(_b("security-auditor", "grep -n 'a;b' x"), CFG).allow
        assert decide(_b("security-auditor", "grep -n '$x' src"), CFG).allow


class TestRound3SortPytestGitleaks:
    @pytest.mark.parametrize(
        "command",
        [
            "sort --out=f x",
            "sort --o=f x",
            "sort --compress-program=gzip x",
            "sort --compress-prog=gzip x",
            "sort -T /tmp x",
            "sort --temporary-directory=/tmp x",
        ],
    )
    def test_sort_denies(self, command: str) -> None:
        assert not decide(_b("security-auditor", command), CFG).allow, command


def test_read_only_bash_judges_the_hook_alone() -> None:
    ro = ("--git", "read-only")
    assert evaluate(HOOK, _b("x", "git log | head"), *ro) is None
    assert evaluate(HOOK, _b("x", "git push"), *ro) == jail.R_AUDITOR_BASH
    assert evaluate(HOOK, _b("x", "git log"), "--git", "specialist") is None
    assert evaluate(HOOK, _b("x", "git status"), "--git", "specialist") == jail.R_SPECIALIST_BASH
    want = "Bash is limited to read-only inspection and git add, commit, diff, log, status."
    assert str(evaluate(HOOK, _b("x", "git push"), "--git", "docs")).startswith(want)
    assert evaluate(HOOK, _b("x", "cat x")) is None
    assert evaluate(HOOK, _b("x", "git log")) is not None


def test_read_only_bash_declares_the_test_runner_flag() -> None:
    # 0109: the flag 0051 reserved now carries the audit and unit test runs.
    flags = load(HOOK).FLAGS
    assert set(flags) == {"--git", "--test-runner"}
    assert flags["--test-runner"].values == {"audit", "unit"}
    bad = run_script(HOOK, payload("Bash", command="ls"), "--test-runner", "all")
    assert bad["decision"] == "deny" and bad["reason"].startswith("hook read_only_bash failed")


def test_read_only_bash_fixture_decisions() -> None:
    log = payload("Bash", command="git log --oneline -3 | head")
    assert run_script(HOOK, log, "--git", "read-only") == {"decision": "allow", "reason": ""}
    rm = payload("Bash", command="rm x")
    want = {"decision": "deny", "reason": jail.R_AUDITOR_BASH}
    assert run_script(HOOK, rm, "--git", "read-only") == want
    status = payload("Bash", command="git status")
    want = {"decision": "deny", "reason": jail.R_SPECIALIST_BASH}
    assert run_script(HOOK, status, "--git", "specialist") == want


def test_read_only_bash_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"), "--git", "read-only")


# spec 6: one allow and one refusal per git read row the read-only grant gains.
GIT_ROWS = [
    ("git grep -n decide -- scripts", "git grep --open-files-in-pager=vi decide"),
    ("git grep -il jail HEAD", "git grep -O decide"),
    ("git worktree list", "git worktree add /tmp/x"),
    ("git worktree list --porcelain", "git worktree remove x"),
    ("git merge-base --is-ancestor main HEAD", "git merge-base --output=x main HEAD"),
    ("git show HEAD:scripts/a.py | sed -n 10,40p", "sed -n 10,40p scripts/a.py"),
    ("git show HEAD:a.py | sed -n 1p", "git show HEAD:a.py | sed -n 1w/tmp/x"),
    ("git show main:a.py | sed -n '5,9p' | head", "git show HEAD:a.py | sed 1,2p"),
    ("git show HEAD:a.py | grep -n x", "git log | sed -n 1p"),
    ("git -C .claude/worktrees/u1 grep -n x", "git show HEAD:a.py ; sed -n 1p"),
]


@pytest.mark.parametrize(("allowed", "refused"), GIT_ROWS)
def test_read_only_grant_git_rows(allowed: str, refused: str) -> None:
    for agent in ("security-auditor", "verifier"):
        assert decide(_b(agent, allowed), CFG).allow, (agent, allowed)
        assert evaluate(HOOK, _b(agent, allowed), "--git", "read-only") is None, allowed
        refusal = evaluate(HOOK, _b(agent, refused), "--git", "read-only")
        assert refusal == jail.R_AUDITOR_BASH, (agent, refused)


def test_specialist_grant_gains_no_git_row() -> None:
    # spec 6: only the read-only grant widens; the specialist set stays diff, show and log.
    for command in ("git grep x", "git worktree list", "git merge-base main HEAD"):
        assert evaluate(HOOK, _b("x", command), "--git", "specialist") == jail.R_SPECIALIST_BASH


# spec 7.1: the Train C read rows of the read-only grant, one allow and one nearest-write refusal.
TRAIN_C_GIT_ROWS = [
    (
        "git -C /work/repo grep -n -P '[\\x{2013}\\x{2014}]' daedalus/t -- agents skills",
        "git grep -P --open-files-in-pager=vi x",
    ),
    ("git -C /work/repo log --oneline --graph a..b", "git log --graph --output=x a..b"),
    ("git log --first-parent --format='%h %s' a..b", "git log --first-parent --output x a..b"),
    ("git branch --list 'daedalus*'", "git branch --list -D daedalus-x"),
]


@pytest.mark.parametrize(("allowed", "refused"), TRAIN_C_GIT_ROWS)
def test_read_only_grant_train_c_git_rows(allowed: str, refused: str) -> None:
    for agent in ("security-auditor", "verifier"):
        assert decide(_b(agent, allowed), CFG).allow, (agent, allowed)
        refusal = evaluate(HOOK, _b(agent, refused), "--git", "read-only")
        assert refusal == jail.R_AUDITOR_BASH, (agent, refused)


@pytest.mark.parametrize(
    "command",
    [
        "git log -S --graph --ext-diff",
        "git log -G --first-parent --textconv",
        "git grep -e -P -Ovi x",
        "git grep -e -nP --open-files-in-pager x",
        "git branch --list --delete daedalus-x",
        "git branch -- --list",
    ],
)
def test_a_stand_in_flag_swallows_the_same_token(command: str) -> None:
    # spec 7.1: a value-taking flag before a new flag still takes it, so the next one is judged.
    assert evaluate(HOOK, _b("x", command), "--git", "read-only") == jail.R_AUDITOR_BASH


def test_specialist_grant_gains_only_the_log_rows() -> None:
    # spec 6, 7.1: grep and branch stay outside the specialist set; its log reads widen.
    spec = ("--git", "specialist")
    assert evaluate(HOOK, _b("x", "git log --graph --first-parent a..b"), *spec) is None
    for command in ("git grep -P x HEAD", "git branch --list 'daedalus*'"):
        assert evaluate(HOOK, _b("x", command), *spec) == jail.R_SPECIALIST_BASH, command


SPECIALIST_CD = "cd /tmp/nist && jq -r '[.. | objects | select(.id?)] | .[] | .id' catalog.json"


@pytest.mark.parametrize("agent", READ_ONLY_AGENTS)
def test_specialist_cd_then_read_is_allowed(agent: str) -> None:
    # spec 7.1, Train C seq 848: one absolute cd heading an && chain of reads.
    assert decide(_b(agent, SPECIALIST_CD), CFG).allow, agent
    assert decide(_b(agent, f"{SPECIALIST_CD} | head -n 40"), CFG).allow, agent
    assert not decide(_b(agent, f"{SPECIALIST_CD} > /tmp/nist/out.json"), CFG).allow, agent


@pytest.mark.parametrize(
    "command",
    [
        "cd /tmp/nist && git log",
        "cd /tmp/nist && git -C /work/repo diff",
        "cd /tmp && python3 -m pytest /tmp/x.py -q",
        "cd /tmp/nist ; jq . catalog.json",
        "cd nist && jq . catalog.json",
        "jq . catalog.json && cd /tmp",
        "cd /tmp && cd /tmp/nist && cat x",
        "pushd /tmp && cat x",
    ],
)
def test_cd_before_git_or_a_test_run_is_refused(command: str) -> None:
    reason = evaluate(HOOK, _b("x", command), "--git", "read-only", "--test-runner", "audit")
    assert reason == load(HOOK).R_CD_CHAIN, command


def test_cd_into_a_credential_store_is_still_refused(cred_home: Path, tmp_path: Path) -> None:
    # spec 7.1: the cd row opens no store and no reply key; credential_paths follows the cd base.
    repo = _key_repo(tmp_path)
    for agent in READ_ONLY_AGENTS:
        store = _b(agent, f"cd {cred_home}/.ssh && cat id_ed25519")
        key = _bash_in(repo, agent, f"cd {repo}/.claude/daedalus && cat reply-hmac.key")
        for hook_input in (store, key):
            reason = str(decide(hook_input, CFG).reason)
            assert "credential path" in reason or "reply key" in reason, (agent, reason)


def test_auditor_sed_on_a_file_stays_refused() -> None:
    # spec 6: sed reads behind git show only; Train C seq 2016 reads line ranges with Read.
    command = "sed -n '325,345p;480,600p' /work/repo/scripts/lib/shell.py"
    assert evaluate(HOOK, _b("x", command), "--git", "read-only") == jail.R_AUDITOR_BASH


TRAIN = "20261017-120000"


def _train_repo(tmp_path: Path, marked: bool = True) -> Path:
    repo = _git_init(tmp_path / "repo")
    if marked:
        write_train_marker(repo)
    return repo


def _rb(repo: Path, agent: str, command: str) -> dict[str, Any]:
    return {**_b(agent, command), "cwd": str(repo)}


AUDIT = ("--git", "read-only", "--test-runner", "audit")
UNIT = ("--git", "read-only", "--test-runner", "unit")


def _places(repo: Path) -> tuple[str, str]:
    return f"{repo}/docs/.tmp/daedalus/{TRAIN}/audit", f"{repo}/.claude/worktrees/{TRAIN}-audit"


def test_audit_test_run_admits_the_audit_folder_and_the_corpus(tmp_path: Path) -> None:
    # pin C4 -> C1: paths under the train's audit folder or the audit worktree's corpus.
    repo = _train_repo(tmp_path)
    audit, tree = _places(repo)
    for command in (
        f"python3 -m pytest {audit}/round1/test_scope_x.py -q",
        f"python3 -m pytest {audit}/round1/test_scope_x.py::test_refused -q -p no:cacheprovider"
        f" --rootdir {tree}",
        f"python3 -m pytest {tree}/tests/adversarial -q -k quoting",
        f"python3 -m pytest {audit}/round2 {tree}/tests/adversarial/test_globs.py -q | tail -n 5",
    ):
        assert evaluate(HOOK, _rb(repo, "security-auditor", command), *AUDIT) is None, command
        assert decide(_rb(repo, "security-auditor", command), CFG).allow, command


def test_audit_test_run_refuses_other_paths(tmp_path: Path) -> None:
    # 0109: every other path, flag or spelling names the one admitted form.
    repo = _train_repo(tmp_path)
    audit, tree = _places(repo)
    (repo / "src").mkdir()
    Path(audit, "round1").mkdir(parents=True)
    Path(audit, "round1", "link").symlink_to(repo / "src")
    want = read_only_bash().R_TEST_RUN.format(
        runner="audit", where=f"{audit} or {tree}/tests/adversarial", rootdir=tree
    )
    for command in (
        f"python3 -m pytest {repo}/tests/test_x.py -q",
        f"python3 -m pytest docs/.tmp/daedalus/{TRAIN}/audit/x.py -q",
        f"python3 -m pytest {audit}/../briefs/x.py -q",
        f"python3 -m pytest {audit}/round1/link/test_x.py -q",
        f"python3 -m pytest {audit}/x.py",
        f"python3 -m pytest {audit}/x.py -q -x",
        f"python3 -m pytest {audit}/x.py -q -p evil",
        f"python3 -m pytest {audit}/x.py -q --rootdir {repo}",
        f"python3 -m pytest {repo}/docs/.tmp/daedalus/20261017-999999/audit/x.py -q",
        f"python3 -m pytest {tree}/tests/test_jail.py -q",
        f"pytest {audit}/x.py -q",
        f"python -m pytest {audit}/x.py -q",
        "python3 -m pytest -q",
    ):
        assert evaluate(HOOK, _rb(repo, "security-auditor", command), *AUDIT) == want, command


def test_test_run_outside_a_train_is_refused(tmp_path: Path) -> None:
    repo = _train_repo(tmp_path, marked=False)
    audit, _ = _places(repo)
    command = f"python3 -m pytest {audit}/x.py -q"
    for runner, flags in (("audit", AUDIT), ("unit", UNIT)):
        want = read_only_bash().R_TEST_RUN_NO_TRAIN.format(runner=runner)
        assert evaluate(HOOK, _rb(repo, "security-auditor", command), *flags) == want


def test_pytest_without_the_runner_grant_is_refused(tmp_path: Path) -> None:
    # spec 3.7: an agent whose hook carries no --test-runner runs no tests.
    repo = _train_repo(tmp_path)
    audit, _ = _places(repo)
    command = f"python3 -m pytest {audit}/x.py -q"
    assert evaluate(HOOK, _rb(repo, "x", command), "--git", "read-only") == jail.R_AUDITOR_BASH
    assert not decide(_rb(repo, "framework-specialist", command), CFG).allow


def test_unit_test_run_admits_only_a_recorded_unit_worktree(tmp_path: Path) -> None:
    # pin C4 -> C1: --test-runner unit binds the run to one worktree the train records.
    from lib import train_state

    repo = _train_repo(tmp_path)
    unit = f"{repo}/.claude/worktrees/{TRAIN}-u1"
    other = f"{repo}/.claude/worktrees/{TRAIN}-u2"
    units = [
        {"name": f"{TRAIN}-u1", "branch": f"daedalus-unit/{TRAIN}-u1", "path": unit},
        {"name": "stray", "branch": "daedalus-unit/stray", "path": f"{tmp_path}/elsewhere"},
    ]
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "units": units})
    ok = f"python3 -m pytest {unit}/tests/test_a.py {unit}/tests -q -p no:cacheprovider"
    assert evaluate(HOOK, _rb(repo, "verifier", f"{ok} --rootdir {unit}"), *UNIT) is None
    assert decide(_rb(repo, "verifier", ok), CFG).allow
    want = read_only_bash().R_TEST_RUN.format(
        runner="unit", where="one unit worktree this train records", rootdir="<that worktree>"
    )
    audit, _ = _places(repo)
    for command in (
        f"python3 -m pytest {other}/tests -q",
        f"python3 -m pytest {unit}/tests -q --rootdir {other}",
        f"python3 -m pytest {tmp_path}/elsewhere/tests -q",
        f"python3 -m pytest {audit}/x.py -q",
    ):
        assert evaluate(HOOK, _rb(repo, "verifier", command), *UNIT) == want, command


def test_unit_test_run_without_train_state_is_refused(tmp_path: Path) -> None:
    repo = _train_repo(tmp_path)
    command = f"python3 -m pytest {repo}/.claude/worktrees/{TRAIN}-u1/tests -q"
    reason = evaluate(HOOK, _rb(repo, "verifier", command), *UNIT)
    assert reason is not None and reason.startswith("the unit test run is")


@pytest.mark.parametrize(
    ("agent", "flags"),
    [
        ("security-auditor", AUDIT),
        ("daedalus:verifier", UNIT),
        ("framework-specialist", ("--git", "specialist")),
        ("x", ()),
    ],
)
def test_basetemp_is_refused_by_name_for_every_agent(
    tmp_path: Path, agent: str, flags: tuple[str, ...]
) -> None:
    # issue 56: the reason names the flag, the agent and the next action, before any grammar.
    repo = _train_repo(tmp_path)
    audit, _ = _places(repo)
    name = agent.removeprefix("daedalus:")
    want = jail.R_BASETEMP_AGENT.format(agent=name)
    for command in (
        f"python3 -m pytest {audit}/x.py -q --basetemp=/tmp/x",
        "pytest --basetemp /tmp/x",
        "git log | python3 -m pytest -q --basetemp=x",
    ):
        assert evaluate(HOOK, _rb(repo, agent, command), *flags) == want, command
    assert f"for {name}:" in want and "Next: drop --basetemp" in want
    grep = "grep -n -e --basetemp scripts/lib/jail.py"
    assert evaluate(HOOK, _rb(repo, agent, grep), *flags) is None


def read_only_bash() -> Any:
    return load(HOOK)


def _audit_units(repo: Path, flagged: bool) -> tuple[str, str]:
    from lib import train_state

    unit = f"{repo}/.claude/worktrees/{TRAIN}-u1"
    _, tree = _places(repo)
    audit: dict[str, object] = {"name": f"{TRAIN}-audit", "branch": "b", "path": tree}
    if flagged:
        audit["audit"] = True
    units = [{"name": f"{TRAIN}-u1", "branch": f"daedalus-unit/{TRAIN}-u1", "path": unit}, audit]
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "units": units})
    return unit, tree


@pytest.mark.parametrize("flagged", [True, False])
def test_unit_test_run_on_the_audit_worktree_is_refused(tmp_path: Path, flagged: bool) -> None:
    # spec 4: the audit worktree is a recorded unit, flagged or (before D2) named, never a bound.
    repo = _train_repo(tmp_path)
    unit, tree = _audit_units(repo, flagged)
    want = read_only_bash().R_TEST_RUN_AUDIT.format(tree=tree)
    for command in (
        f"python3 -m pytest {tree}/tests -q",
        f"python3 -m pytest {tree}/tests/adversarial/test_x.py::test_y -q --rootdir {tree}",
        f"python3 -m pytest {unit}/tests -q --rootdir {tree}",
    ):
        assert evaluate(HOOK, _rb(repo, "verifier", command), *UNIT) == want, command
        assert not decide(_rb(repo, "verifier", command), CFG).allow, command
    assert "Next: run the tests under the unit worktree you verify" in want


def test_unit_test_run_admits_a_coder_worktree_beside_the_audit_unit(tmp_path: Path) -> None:
    # spec 4: excluding the audit worktree leaves every coder unit worktree admitted.
    repo = _train_repo(tmp_path)
    unit, _ = _audit_units(repo, flagged=True)
    command = f"python3 -m pytest {unit}/tests -q -p no:cacheprovider --rootdir {unit}"
    assert evaluate(HOOK, _rb(repo, "verifier", command), *UNIT) is None
    assert decide(_rb(repo, "verifier", command), CFG).allow


def test_audit_test_run_still_reads_the_audit_worktree_corpus(tmp_path: Path) -> None:
    # spec 4: the unit refusal leaves the auditor's --test-runner audit form unchanged.
    repo = _train_repo(tmp_path)
    _, tree = _audit_units(repo, flagged=True)
    command = f"python3 -m pytest {tree}/tests/adversarial -q --rootdir {tree}"
    assert evaluate(HOOK, _rb(repo, "security-auditor", command), *AUDIT) is None


def test_a_rewritten_search_word_or_rg_program_option_names_its_reason() -> None:
    # prepush2-2026-10-27 items 1 and 2: the read check alone refuses both, whatever the target.
    ro = ("--git", "read-only")
    for command in ("rg $'-uu' -l x src", 'grep $"-r" x src', "rg {-uu,} x src", "rg x *"):
        assert evaluate(HOOK, _b("x", command), *ro) == jail.R_RG_OPAQUE, command
    for command in ("rg --hostname-bin=/tmp/x -n x src", "rg --pre /tmp/x x src"):
        assert evaluate(HOOK, _b("x", command), *ro) == jail.R_RG_PROGRAM, command
    for command in ("rg -n 'a$' src", "rg -g '*.{tf,yml}' x src", "rg -n x src/*.py"):
        assert evaluate(HOOK, _b("x", command), *ro) is None, command
