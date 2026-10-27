# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0048, spec W3.4: the kernel wrapper's rules on this kernel, and the confine check around it.
from __future__ import annotations

import ctypes
import errno
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import daedalus_confine
import pytest
from lib import shell

from tests.adversarial.corpus import (
    CONFINE_RUNNERS,
    UNIX_SOCKETS,
    UNUSABLE_KERNEL,
    assert_denied,
)
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
NO_LANDLOCK = daedalus_confine.Support("x86_64", 0, False)
PROBE_ERROR = daedalus_confine.Support("x86_64", 3, False, "seccomp probe: boom")
REAL_JUDGE = load("confine").judge
# 0048, issue 87: the WSL2 interop socket a confined command must never reach.
INTEROP = os.environ.get("WSL_INTEROP", "/run/WSL/1_interop")


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


@pytest.fixture(autouse=True)
def _confine_check_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0048, issue 86: conftest drops the confine check from the test chain; these tests judge it.
    monkeypatch.setattr(load("confine"), "judge", REAL_JUDGE)


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
    # 0048: the wrapper runs on this interpreter, so its grants hold the venv the command needs.
    lead = [sys.executable, str(shell.CONFINE_PATH)]
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
    assert "refused=socket(AF_INET,AF_INET6,AF_UNIX,any family but AF_NETLINK),io_uring" in first
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
@pytest.mark.parametrize("family", ["AF_INET", "AF_INET6", "AF_VSOCK", "AF_UNIX"])
def test_a_socket_is_refused_and_socketpair_and_netlink_open(tmp_path: Path, family: str) -> None:
    # 0048, issue 87: socketpair() never reaches a daemon, so it stays open.
    _, unit = _unit(tmp_path)
    code = (
        "import socket\nfor s in socket.socketpair():\n    s.close()\n"
        "socket.socket(socket.AF_NETLINK, socket.SOCK_RAW).close()\nprint('local ok')\n"
        f"socket.socket(socket.{family}, socket.SOCK_STREAM)"
    )
    done = _confined(unit, code)
    assert done.stdout.splitlines()[1:] == ["local ok"], done.stderr
    assert done.returncode == 1 and "PermissionError: [Errno 1]" in done.stderr


@needs_kernel
@pytest.mark.parametrize("code", UNIX_SOCKETS)
def test_a_unix_socket_opened_inside_the_wrapper_is_refused(tmp_path: Path, code: str) -> None:
    _, unit = _unit(tmp_path)
    done = _confined(unit, code)
    assert done.returncode == 1 and "PermissionError: [Errno 1]" in done.stderr, done.stderr


@needs_kernel
@pytest.mark.skipif(not _is_socket(INTEROP), reason="no WSL2 interop socket on this machine")
def test_the_wsl2_interop_socket_is_unreachable_inside_the_wrapper(tmp_path: Path) -> None:
    # 0048, issue 87: the interop socket runs Windows programs outside every Linux rule.
    _, unit = _unit(tmp_path)
    code = f"import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect({INTEROP!r})"
    done = _confined(unit, code)
    assert done.returncode == 1 and "PermissionError: [Errno 1]" in done.stderr, done.stderr


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
    # issue 87: AF_UNIX (1) is no longer a jump target; only AF_NETLINK (16) reaches the allow.
    assert prog[12:] == [
        (jeq, 1, 0, 41),
        (ret, 0, 0, allow),
        (ld, 0, 0, 16),
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
    assert err.startswith(f"daedalus_confine: {sys.platform} on riscv64 has no modelled syscall")
    assert daedalus_confine.KERNEL_NEED in err and daedalus_confine.NEXT_KERNEL in err


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


@pytest.mark.parametrize("support", [OFF, NO_LANDLOCK])
@pytest.mark.parametrize("template", UNUSABLE_KERNEL)
def test_the_check_refuses_a_test_command_without_landlock(
    monkeypatch: pytest.MonkeyPatch, support: daedalus_confine.Support, template: str
) -> None:
    # 0048, issue 86: no step-aside; the Next line names the kernel requirement.
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: support)
    hook_input = _b("repo-coder", f"cd {WT} && " + template.format(wrap=WRAP))
    reason = str(evaluate("confine", hook_input))
    assert daedalus_confine.KERNEL_NEED in reason and daedalus_confine.NEXT_KERNEL in reason
    assert_denied(hook_input, daedalus_confine.KERNEL_NEED)


@pytest.mark.parametrize("template", UNUSABLE_KERNEL)
def test_the_check_refuses_a_test_command_with_the_probe_error_text(
    monkeypatch: pytest.MonkeyPatch, template: str
) -> None:
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: PROBE_ERROR)
    hook_input = _b("repo-coder", f"cd {WT} && " + template.format(wrap=WRAP))
    reason = str(evaluate("confine", hook_input))
    assert "the kernel rules probe failed: seccomp probe: boom" in reason
    assert daedalus_confine.NEXT_PROBE in reason
    assert_denied(hook_input, "seccomp probe: boom")


@pytest.mark.parametrize("support", [OFF, NO_LANDLOCK, PROBE_ERROR])
def test_other_commands_pass_on_an_unusable_kernel(
    monkeypatch: pytest.MonkeyPatch, support: daedalus_confine.Support
) -> None:
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: support)
    assert evaluate("confine", _b("repo-coder", f"cd {WT} && git -C {WT} status")) is None


def test_the_wrapper_refuses_to_run_on_a_probe_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: PROBE_ERROR)
    assert daedalus_confine.main(["--unit", str(WT), "--", "true"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("daedalus_confine: the kernel rules probe failed: seccomp probe: boom")


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize("command", CONFINE_RUNNERS)
def test_each_new_runner_needs_the_wrapper(command: str) -> None:
    # 0048, issue 91: bare, the runner is refused; wrapped, the confine check passes it.
    bare = _b("repo-coder", f"cd {WT} && {command}")
    assert evaluate("confine", bare) == load("confine").R_CONFINE
    assert_denied(bare)
    assert evaluate("confine", _b("repo-coder", f"cd {WT} && {WRAP} {command}")) is None


@pytest.mark.usefixtures("kernel")
@pytest.mark.parametrize(
    "command", ["go build ./...", "cargo build", "uv pip list", "go vet ./...", "uvx ruff"]
)
def test_a_runner_name_without_its_test_verb_needs_no_wrapper(command: str) -> None:
    assert evaluate("confine", _b("repo-coder", f"cd {WT} && {command}")) is None


class _Libc:
    # 0048, issue 86: stands in for libc; syscall answers -1 with the errno it was given.
    def __init__(self, result: int, code: int = 0) -> None:
        self.result, self.code = result, code

    def syscall(self, *_: object) -> int:
        if self.code:
            ctypes.set_errno(self.code)
        return self.result


@pytest.mark.parametrize("abi", [1, 3, 6])
def test_landlock_abi_reports_the_kernel_answer(monkeypatch: pytest.MonkeyPatch, abi: int) -> None:
    monkeypatch.setattr(daedalus_confine, "_libc", lambda: _Libc(abi))
    monkeypatch.setattr(daedalus_confine, "_call", lambda func, *args: func(*args))
    assert daedalus_confine.landlock_abi() == abi


@pytest.mark.parametrize("code", sorted(daedalus_confine.LANDLOCK_ABSENT))
def test_landlock_abi_is_0_only_for_the_absent_errors(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(daedalus_confine, "_libc", lambda: _Libc(-1, code))
    monkeypatch.setattr(daedalus_confine, "_call", lambda func, *args: func(*args))
    assert daedalus_confine.landlock_abi() == 0


@pytest.mark.parametrize("code", [errno.EPERM, errno.EFAULT, errno.EINVAL, errno.ENOMEM])
def test_landlock_abi_surfaces_any_other_error(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    monkeypatch.setattr(daedalus_confine, "_libc", lambda: _Libc(-1, code))
    monkeypatch.setattr(daedalus_confine, "_call", lambda func, *args: func(*args))
    with pytest.raises(OSError, match=f"landlock version probe: {os.strerror(code)}"):
        daedalus_confine.landlock_abi()


def test_landlock_abi_surfaces_a_libc_load_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> None:
        raise OSError("no libc here")

    monkeypatch.setattr(daedalus_confine, "_libc", broken)
    with pytest.raises(OSError, match="no libc here"):
        daedalus_confine.landlock_abi()


def _support(monkeypatch: pytest.MonkeyPatch, abi: object, probe: object) -> object:
    # 0048, issue 86: runs the real kernel_support over stand-in probes; each may raise.
    def answer(value: object) -> object:
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(daedalus_confine, "kernel_support", PROBE)
    monkeypatch.setattr(daedalus_confine.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(daedalus_confine, "landlock_abi", lambda: answer(abi))
    monkeypatch.setattr(daedalus_confine, "_seccomp_probe", lambda arch: answer(probe))
    PROBE.cache_clear()
    try:
        return PROBE()
    finally:
        PROBE.cache_clear()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the probe models Linux only")
@pytest.mark.parametrize(
    ("abi", "probe", "expected"),
    [
        (3, None, daedalus_confine.Support("x86_64", 3, True)),
        (0, None, daedalus_confine.Support("x86_64", 0, False)),
        (
            OSError(errno.EPERM, "landlock version probe: denied"),
            None,
            daedalus_confine.Support(
                "x86_64", 0, False, "landlock probe: [Errno 1] landlock version probe: denied"
            ),
        ),
        (
            3,
            OSError(errno.EAGAIN, "fork"),
            daedalus_confine.Support("x86_64", 3, False, "seccomp probe: [Errno 11] fork"),
        ),
        (3, "seccomp probe: x", daedalus_confine.Support("x86_64", 3, False, "seccomp probe: x")),
    ],
    ids=["ok", "landlock-absent", "landlock-error", "seccomp-oserror", "seccomp-failed"],
)
def test_kernel_support_keeps_each_probe_branch(
    monkeypatch: pytest.MonkeyPatch, abi: object, probe: object, expected: object
) -> None:
    assert _support(monkeypatch, abi, probe) == expected


@pytest.mark.parametrize(
    ("support", "words"),
    [
        (ON, None),
        (OFF, daedalus_confine.NEXT_KERNEL),
        (NO_LANDLOCK, "this kernel serves no Landlock ABI"),
        (PROBE_ERROR, daedalus_confine.NEXT_PROBE),
        (daedalus_confine.Support("x86_64", 3, False), "the kernel rules probe failed"),
    ],
)
def test_unusable_names_the_cause(support: daedalus_confine.Support, words: str | None) -> None:
    cause = daedalus_confine.unusable(support)
    assert cause is None if words is None else words in str(cause)


def _child(monkeypatch: pytest.MonkeyPatch, install: object, opened: object) -> str:
    # 0048, issue 86: _probe_child over stand-ins, so this process never takes the filter.
    def act(value: object) -> object:
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(daedalus_confine, "_libc", lambda: None)
    monkeypatch.setattr(daedalus_confine, "_no_new_privs", lambda libc: None)
    monkeypatch.setattr(daedalus_confine, "_install_filter", lambda libc, arch: act(install))
    monkeypatch.setattr(daedalus_confine.socket, "socket", lambda *a: act(opened))
    return daedalus_confine._probe_child(daedalus_confine.ARCHES["x86_64"])


def test_the_probe_child_proves_the_filter_only_on_eperm(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = PermissionError(errno.EPERM, "Operation not permitted")
    assert _child(monkeypatch, None, refused) == ""
    opened = SimpleNamespace(close=lambda: None)
    failed = _child(monkeypatch, None, opened)
    assert failed == "seccomp probe: an AF_INET socket opened under the filter"
    error = _child(monkeypatch, OSError(errno.EINVAL, "seccomp: Invalid argument"), None)
    assert error == "seccomp probe: [Errno 22] seccomp: Invalid argument"


@pytest.mark.parametrize(
    ("child", "expected"),
    [
        ("", None),
        ("seccomp probe: x", "seccomp probe: x"),
        (RuntimeError("boom"), "seccomp probe: the probe child exited with status 1"),
    ],
    ids=["proved", "reported", "child-crashed"],
)
def test_the_seccomp_probe_reads_the_child_report(
    monkeypatch: pytest.MonkeyPatch, child: object, expected: str | None
) -> None:
    def report(arch: daedalus_confine.Arch) -> object:
        if isinstance(child, Exception):
            raise child
        return child

    monkeypatch.setattr(daedalus_confine, "_probe_child", report)
    assert daedalus_confine._seccomp_probe(daedalus_confine.ARCHES["x86_64"]) == expected


@needs_kernel
def test_the_live_seccomp_probe_proves_the_filter() -> None:
    arch = daedalus_confine.ARCHES[daedalus_confine.platform.machine()]
    assert daedalus_confine._seccomp_probe(arch) is None


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
    # 0134: the docs writer carries the repo-coder's list, so it carries confine too.
    assert carriers == {"repo-coder", "docs-writer"}


def test_confine_hook_standard_properties() -> None:
    inside = payload("Bash", command=f"cd {WT} && {WRAP} pytest -q")
    outside_tools_allow("confine", "Read")
    unknown_flag_denies("confine", inside)
    malformed_input_denies("confine")
    internal_error_denies("confine", inside)
