# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0048, spec W3.4: the kernel wrapper's rules on this kernel, and the confine check around it.
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import daedalus_confine
import pytest
from lib import shell

from tests.conftest import CFG, CWD, WT
from tests.hook_chain import (
    CHAINS,
    decide,
    evaluate,
    internal_error_denies,
    load,
    malformed_input_denies,
    outside_tools_allow,
    payload,
    unknown_flag_denies,
)
from tests.jail_cases import _narrowed_repo
from tests.payloads import _b, _cwd

pytestmark = pytest.mark.usefixtures("jail_fakes")
PROBE = daedalus_confine.kernel_support
LIVE = PROBE().ok
needs_kernel = pytest.mark.skipif(not LIVE, reason="this kernel cannot hold the rules")
WRAP = f"{shell.CONFINE_PATH} --unit {WT} --"
ON = daedalus_confine.Support("x86_64", 3, True)
OFF = daedalus_confine.Support(None, 0, False)


@pytest.fixture
def kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0048: the shared fixture turns the probe off; these tests judge with it on.
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: ON)


def _unit(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    (repo / "service-manifest.json").write_text("{}", encoding="utf-8")
    (repo / ".claude" / "daedalus").mkdir()
    (repo / ".claude" / "daedalus" / "reply-hmac.key").write_text("k", encoding="utf-8")
    return repo, unit


def _confined(
    unit: Path, code: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    # 0048: by the wrapper's own path; with env, through this interpreter so HOME may move.
    lead = [str(shell.CONFINE_PATH)] if env is None else [sys.executable, str(shell.CONFINE_PATH)]
    argv = [*lead, "--unit", str(unit), "--", sys.executable, "-c", code]
    return subprocess.run(argv, capture_output=True, text=True, check=False, cwd=unit, env=env)


@needs_kernel
def test_the_first_line_is_the_rule_set_applied(tmp_path: Path) -> None:
    _, unit = _unit(tmp_path)
    done = _confined(unit, "print('ran')")
    assert done.returncode == 0, done.stderr
    first, second = done.stdout.splitlines()
    support = PROBE()
    tmp = daedalus_confine._private_tmp(str(unit))
    real, repo = daedalus_confine._unit(str(unit))
    assert first == daedalus_confine.rule_set(real, repo, tmp, support).line()
    assert first.startswith(f"daedalus_confine: abi={support.abi} arch={support.arch} rw={real},")
    assert f"ro={repo}(-.claude/daedalus,-.claude/worktrees)," in first
    assert "refused=socket(AF_INET,AF_INET6,any family but AF_UNIX,AF_NETLINK),io_uring" in first
    assert second == "ran"
    assert f"git_config={tmp}/gitconfig xdg_config={tmp}/config" in first
    assert f"{Path.home()}/.gitconfig" not in first and f"{Path.home()}/.config" not in first


@needs_kernel
def test_git_stores_and_config_are_unreadable_and_git_still_runs(tmp_path: Path) -> None:
    # 0048: no grant under the home folder; git reads the wrapper's empty config instead.
    _, unit = _unit(tmp_path)
    home = tmp_path / "home"
    files = [home / ".git-credentials", home / ".config/git/credentials", home / ".gitconfig"]
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("https://u:token@example.invalid\n", encoding="utf-8")
    code = (
        "import subprocess\n"
        f"for path in {[str(p) for p in files]!r}:\n"
        "    try:\n        open(path).read(); print('read', path)\n"
        "    except PermissionError:\n        print('refused')\n"
        f"print(subprocess.run(['git', 'init', '-q', {str(unit / 'r')!r}]).returncode)"
    )
    env = {**os.environ, "HOME": str(home)}
    env.pop("XDG_CONFIG_HOME", None)
    done = _confined(unit, code, env)
    assert done.stdout.splitlines()[1:] == ["refused", "refused", "refused", "0"], done.stderr
    assert (unit / "r" / ".git").is_dir()


@needs_kernel
def test_a_write_outside_the_worktree_is_refused(tmp_path: Path) -> None:
    repo, unit = _unit(tmp_path)
    outside, inside = repo / "outside.txt", unit / "inside.txt"
    code = f"open({str(inside)!r}, 'w').write('x'); open({str(outside)!r}, 'w')"
    done = _confined(unit, code)
    assert done.returncode == 1 and "PermissionError" in done.stderr
    assert inside.read_text(encoding="utf-8") == "x" and not outside.exists()


@needs_kernel
def test_the_data_folder_is_unreadable_and_the_repo_readable(tmp_path: Path) -> None:
    repo, unit = _unit(tmp_path)
    key = repo / ".claude" / "daedalus" / "reply-hmac.key"
    readable = _confined(unit, f"print(open({str(repo / 'service-manifest.json')!r}).read())")
    assert readable.returncode == 0 and readable.stdout.splitlines()[1] == "{}"
    done = _confined(unit, f"open({str(key)!r}).read()")
    assert done.returncode == 1 and "PermissionError" in done.stderr


@needs_kernel
@pytest.mark.parametrize("family", ["AF_INET", "AF_INET6", "AF_VSOCK"])
def test_an_inet_socket_is_refused_and_a_unix_socket_opens(tmp_path: Path, family: str) -> None:
    _, unit = _unit(tmp_path)
    code = (
        "import socket\nsocket.socket(socket.AF_UNIX).close()\n"
        "socket.socket(socket.AF_NETLINK, socket.SOCK_RAW).close()\nprint('unix ok')\n"
        f"socket.socket(socket.{family}, socket.SOCK_STREAM)"
    )
    done = _confined(unit, code)
    assert done.stdout.splitlines()[1:] == ["unix ok"]
    assert done.returncode == 1 and "PermissionError: [Errno 1]" in done.stderr


def test_the_filter_kills_a_foreign_arch_and_refuses_x32_and_io_uring() -> None:
    prog = daedalus_confine.socket_filter(daedalus_confine.ARCHES["x86_64"])
    ld, jeq, jge, ret = (
        daedalus_confine.LD_W_ABS,
        daedalus_confine.JEQ_K,
        daedalus_confine.JGE_K,
        daedalus_confine.RET_K,
    )
    deny, allow = daedalus_confine.DENY, daedalus_confine.RET_ALLOW
    assert prog[:4] == [
        (ld, 0, 0, 4),
        (jeq, 1, 0, 0xC000003E),
        (ret, 0, 0, daedalus_confine.RET_KILL_PROCESS),
        (ld, 0, 0, 0),
    ]
    assert prog[4:6] == [(jge, 0, 1, 0x40000000), (ret, 0, 0, deny)]
    assert prog[6:12] == [
        (jeq, 0, 1, 425),
        (ret, 0, 0, deny),
        (jeq, 0, 1, 426),
        (ret, 0, 0, deny),
        (jeq, 0, 1, 427),
        (ret, 0, 0, deny),
    ]
    assert prog[12:] == [
        (jeq, 1, 0, 41),
        (ret, 0, 0, allow),
        (ld, 0, 0, 16),
        (jeq, 2, 0, 1),
        (jeq, 1, 0, 16),
        (ret, 0, 0, deny),
        (ret, 0, 0, allow),
    ]
    arm = daedalus_confine.socket_filter(daedalus_confine.ARCHES["aarch64"])
    assert arm[1] == (jeq, 1, 0, 0xC00000B7) and (jeq, 1, 0, 198) in arm
    assert not any(op[0] == jge for op in arm)


def test_an_unmodelled_architecture_is_refused_with_a_next_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _, unit = _unit(tmp_path)
    monkeypatch.setattr(daedalus_confine, "kernel_support", PROBE)
    monkeypatch.setattr(daedalus_confine.platform, "machine", lambda: "riscv64")
    PROBE.cache_clear()
    try:
        assert PROBE() == OFF
        code = daedalus_confine.main(["--unit", str(unit), "--", "true"])
    finally:
        PROBE.cache_clear()
    err = capsys.readouterr().err
    assert code == 1
    assert err.startswith("daedalus_confine: architecture riscv64 has no modelled syscall table.")
    assert "Next: run the command without the wrapper" in err


@pytest.mark.parametrize(
    "argv",
    [[], ["--unit", "/x"], ["--unit", "/x", "true"], ["--unit=/x", "--", "true"], ["--", "true"]],
)
def test_any_other_wrapper_form_is_refused_with_a_next_line(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert daedalus_confine.main(argv) == 1
    err = capsys.readouterr().err
    assert err.startswith("daedalus_confine: usage:") and shell.CONFINE_NEXT in err


@needs_kernel
def test_a_unit_outside_the_worktrees_folder_is_refused(tmp_path: Path) -> None:
    repo, _ = _unit(tmp_path)
    done = _confined(repo, "print('ran')")
    assert done.returncode == 1 and done.stdout == ""
    assert f"--unit {repo} is not a unit worktree of {repo}." in done.stderr


def test_the_check_steps_aside_without_kernel_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    command = f"cd {WT} && python3 -m pytest tests -q"
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: OFF)
    assert evaluate("confine", _b("repo-coder", command)) is None
    assert decide(_b("repo-coder", command), CFG).allow
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: ON)
    assert evaluate("confine", _b("repo-coder", command)) is not None


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && python3 -m pytest tests -q",
        f"cd {WT} && python3 -m mypy scripts",
        f"cd {WT} && pytest -q 2>&1 | tail -3",
        f"cd {WT} && python3 {WT}/scripts/catalog.py matrix",
        f"cd {WT} && .venv/bin/pytest -q",
        "npm test",
        f"{WT}/scripts/run.sh",
        f"cd {WT} && ./scripts/run.sh",
        f"cd {WT}/scripts && ../scripts/daedalus_doctor.py",
    ],
)
def test_unwrapped_test_command_is_refused_when_the_kernel_holds_rules(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", command)) == load("confine").R_CONFINE


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && {WRAP} python3 -m pytest tests -q",
        f"cd {WT} && {WRAP} python3 -m pytest tests -q 2>&1 | tail -3",
        f"cd {WT}/tests && {WRAP} python3 -m pytest -q",
        f"cd {WT} && {WRAP} python3 {WT}/scripts/catalog.py matrix",
        f"cd {WT} && {WRAP} ./scripts/run.sh",
        f"cd {WT} && {WRAP} {WT}/scripts/run.sh",
    ],
)
def test_the_wrapped_form_passes_the_whole_coder_chain(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", command)) is None
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize("declared", ["make test", "tox -e py312"])
def test_a_declared_non_runner_test_command_needs_the_wrapper(
    tmp_path: Path, declared: str
) -> None:
    repo, wt = _narrowed_repo(tmp_path, json.dumps({"stack": {"unit_test_cmd": declared}}))
    bare = _cwd(_b("repo-coder", f"cd {wt} && {declared}"), repo)
    assert evaluate("confine", bare) == load("confine").R_CONFINE
    command = f"cd {wt} && {shell.CONFINE_PATH} --unit {wt} -- {declared}"
    wrapped = _cwd(_b("repo-coder", command), repo)
    assert evaluate("confine", wrapped) is None
    assert decide(wrapped, CFG).allow, decide(wrapped, CFG).reason


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && git -C {WT} status",
        f"ls {WT}",
        f"sha256sum {WT}/README.md",
        f"cd {WT} && grep -rn x {WT}/scripts",
    ],
)
def test_other_commands_never_need_the_wrapper(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", command)) is None


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && {shell.CONFINE_PATH} --unit {CWD}/.claude/worktrees/u1 -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit {CWD}/.claude/worktrees/zz -- pytest -q",
        f"cd {CWD} && {shell.CONFINE_PATH} --unit {WT} -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit {WT}/tests -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit tests -- pytest -q",
    ],
)
def test_wrapper_unit_must_be_the_command_worktree(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", command)) == load("confine").R_CONFINE_UNIT


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && {WT}/scripts/daedalus_confine.py --unit {WT} -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit={WT} -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} -- pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit {WT} pytest -q",
        f"cd {WT} && {shell.CONFINE_PATH} --unit {WT} --",
    ],
)
def test_a_wrapper_copy_or_another_form_is_refused(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", command)) == shell.R_CONFINE_FORM
    assert not decide(_b("repo-coder", command), CFG).allow


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "inner", ["python3 -c 'print(1)'", "bash -c ls", "timeout 5 pytest -q", "claude -p x"]
)
def test_the_wrapper_grants_nothing_the_bare_command_lacks(inner: str) -> None:
    assert not decide(_b("repo-coder", f"cd {WT} && {WRAP} {inner}"), CFG).allow
    assert not decide(_b("repo-coder", f"cd {WT} && {inner}"), CFG).allow


def test_only_the_coder_carries_the_confine_check() -> None:
    # 0048, Plan 6 section 10.3: the verifier's and auditor's --test-runner forms stay untouched.
    carriers = {name for name, chain in CHAINS.items() if any(s == "confine" for s, _ in chain)}
    assert carriers == {"repo-coder"}


def test_confine_hook_standard_properties() -> None:
    inside = payload("Bash", command=f"cd {WT} && {WRAP} pytest -q")
    outside_tools_allow("confine", "Read")
    unknown_flag_denies("confine", inside)
    malformed_input_denies("confine")
    internal_error_denies("confine", inside)
