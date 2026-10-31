#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0048, spec W3.4: daedalus_confine.py --unit <worktree> -- <command...> applies Landlock path
# rules and a seccomp socket filter to its own process, then replaces itself with the command.
# Children inherit the rules and they end with the process tree; nothing is installed.
# Every number is read from this machine's uapi headers under /usr/include, cited per line.
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import platform
import site
import socket
import stat
import struct
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import shell  # noqa: E402
from lib.config import ConfigError, load_config  # noqa: E402
from lib.credential_paths import credential_roots  # noqa: E402
from lib.jail import UNIT_WORKTREES  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.shell import CONFINE, CONFINE_NEXT, confine_split  # noqa: E402

# x86_64/asm/unistd_64.h:359-361 and asm-generic/unistd.h:801-806 carry the same three.
NR_CREATE_RULESET = 444
NR_ADD_RULE = 445
NR_RESTRICT_SELF = 446
CREATE_RULESET_VERSION = 1 << 0  # linux/landlock.h:50
RULE_PATH_BENEATH = 1  # linux/landlock.h:64
FS_EXECUTE = 1 << 0  # linux/landlock.h:213
FS_WRITE_FILE = 1 << 1  # linux/landlock.h:214
FS_READ_FILE = 1 << 2  # linux/landlock.h:215
FS_READ_DIR = 1 << 3  # linux/landlock.h:216
FS_TRUNCATE = 1 << 14  # linux/landlock.h:227, ABI 3 (:148)
# linux/landlock.h:213-227: ABI 1 knows bits 0-12, ABI 2 adds REFER (13, :173), ABI 3 TRUNCATE.
FS_BY_ABI = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1}
READ_ONLY = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE  # linux/landlock.h:133-148
NET_TCP = (1 << 0) | (1 << 1)  # linux/landlock.h:246-247, bind and connect
NET_ABI = 4  # linux/landlock.h:237: network rules arrive with ABI 4
PR_SET_SECCOMP = 22  # linux/prctl.h:68
PR_SET_NO_NEW_PRIVS = 38  # linux/prctl.h:175
SECCOMP_MODE_FILTER = 2  # linux/seccomp.h:12
RET_KILL_PROCESS = 0x80000000  # linux/seccomp.h:38
RET_ERRNO = 0x00050000  # linux/seccomp.h:42
RET_ALLOW = 0x7FFF0000  # linux/seccomp.h:46
LD_W_ABS = 0x00 | 0x00 | 0x20  # linux/bpf_common.h:7, :18, :24
JEQ_K = 0x05 | 0x10 | 0x00  # linux/bpf_common.h:12, :45, :50
JGE_K = 0x05 | 0x30 | 0x00  # linux/bpf_common.h:12, :47, :50
RET_K = 0x06 | 0x00  # linux/bpf_common.h:13, :50
# linux/seccomp.h:62-66: nr at 0, arch at 4, args[0] at 16, low word first on both arches.
OFF_NR, OFF_ARCH, OFF_ARG0 = 0, 4, 16
DENY = RET_ERRNO | errno.EPERM
# 0048, issue 87: AF_NETLINK only asks the kernel; AF_UNIX socket() is refused, socketpair() not.
LOCAL_FAMILY = int(socket.AF_NETLINK)
# 0048, issue 86: the errors meaning the kernel lacks Landlock; any other probe error is surfaced.
LANDLOCK_ABSENT = frozenset({errno.ENOSYS, errno.EOPNOTSUPP})
SYSTEM_RO = ("/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev")
DEVICES_RW = ("/dev/null",)
# 0048: git exits 128 on an unreadable user config, so it reads an empty one in the temp folder.
GIT_CONFIG = "gitconfig"
XDG_CONFIG = "config"
HIDDEN = (".claude/daedalus", f"{UNIT_WORKTREES}")
NEXT_FORM = CONFINE_NEXT
KERNEL_NEED = (
    "a coder's test command runs only under the kernel wrapper, which needs Linux on x86_64 or "
    "aarch64 with Landlock ABI 1 or later and seccomp filters (0048, issue 86)"
)
NEXT_KERNEL = (
    "Next: commit WIP and yield with this line; the operator boots a kernel with Landlock "
    "enabled (landlock in the lsm= list) and reruns the doctor."
)
NEXT_PROBE = (
    "Next: commit WIP and yield with this line; the operator reruns the doctor and fixes the "
    "cause it names."
)


@dataclass(frozen=True)
class Arch:
    audit: int
    socket: int
    io_uring: tuple[int, ...]
    x32: int


# x86_64: linux/audit.h:442, asm/unistd_64.h:45 and :340-342, asm/unistd.h:13 (x32 bit).
# aarch64: linux/audit.h:390, asm-generic/unistd.h:522, :759-764; arm64 unistd_64.h is built from
# torvalds/linux scripts/syscall.tbl (Makefile.asm-headers); seccomp.h:56 arch is AUDIT_ARCH_*.
ARCHES: dict[str, Arch] = {
    "x86_64": Arch(0xC000003E, 41, (425, 426, 427), 0x40000000),
    "aarch64": Arch(0xC00000B7, 198, (425, 426, 427), 0),
}


class Refusal(Exception):
    pass


@dataclass(frozen=True)
class Support:
    arch: str | None
    abi: int
    seccomp: bool
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.arch is not None and self.abi >= 1 and self.seccomp and not self.error


@dataclass(frozen=True)
class RuleSet:
    abi: int
    arch: str
    repo: str
    rw: tuple[str, ...]
    ro: tuple[str, ...]
    tmp: str

    def line(self) -> str:
        net = "landlock-tcp," if self.abi >= NET_ABI else ""
        hidden = ",".join(f"-{h}" for h in HIDDEN)
        return (
            f"daedalus_confine: abi={self.abi} arch={self.arch} rw={','.join(self.rw)} "
            f"ro={self.repo}({hidden}),{','.join(self.ro)} "
            f"refused={net}socket(AF_INET,AF_INET6,AF_UNIX,any family but AF_NETLINK),io_uring "
            f"tmpdir={self.tmp} git_config={os.path.join(self.tmp, GIT_CONFIG)} "
            f"xdg_config={os.path.join(self.tmp, XDG_CONFIG)}"
        )


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    return libc


def _check(result: int, what: str) -> int:
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, f"{what}: {os.strerror(code)}")
    return result


Arg = int | ctypes.Array[ctypes.c_char] | None


def _call(func: Callable[..., int], *args: Arg) -> int:
    # 0048: syscall and prctl are variadic; every int goes as a full long, never a C int.
    wide = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    return int(func(*wide))


def landlock_abi() -> int:
    # 0048, issue 86: the highest Landlock ABI this kernel serves; 0 only on a LANDLOCK_ABSENT.
    libc = _libc()
    try:
        return _check(
            _call(libc.syscall, NR_CREATE_RULESET, None, 0, CREATE_RULESET_VERSION),
            "landlock version probe",
        )
    except OSError as exc:
        if exc.errno in LANDLOCK_ABSENT:
            return 0
        raise


def socket_filter(arch: Arch) -> list[tuple[int, int, int, int]]:
    # 0048, issue 87: a foreign arch is killed; x32 numbers, io_uring and every socket() family but
    # AF_NETLINK (AF_INET, AF_INET6, AF_UNIX and AF_VSOCK among them) fail with EPERM.
    prog = [(LD_W_ABS, 0, 0, OFF_ARCH), (JEQ_K, 1, 0, arch.audit), (RET_K, 0, 0, RET_KILL_PROCESS)]
    prog.append((LD_W_ABS, 0, 0, OFF_NR))
    if arch.x32:
        prog += [(JGE_K, 0, 1, arch.x32), (RET_K, 0, 0, DENY)]
    for nr in arch.io_uring:
        prog += [(JEQ_K, 0, 1, nr), (RET_K, 0, 0, DENY)]
    prog += [(JEQ_K, 1, 0, arch.socket), (RET_K, 0, 0, RET_ALLOW), (LD_W_ABS, 0, 0, OFF_ARG0)]
    prog.append((JEQ_K, 1, 0, LOCAL_FAMILY))
    return prog + [(RET_K, 0, 0, DENY), (RET_K, 0, 0, RET_ALLOW)]


def _no_new_privs(libc: ctypes.CDLL) -> None:
    _check(_call(libc.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs")


def _install_filter(libc: ctypes.CDLL, arch: Arch) -> None:
    prog = socket_filter(arch)
    # linux/filter.h:24-29: struct sock_filter is u16 code, u8 jt, u8 jf, u32 k.
    raw = ctypes.create_string_buffer(b"".join(struct.pack("=HBBI", *op) for op in prog))
    # linux/filter.h:31-34: struct sock_fprog is a u16 length, then the pointer, natively aligned.
    fprog = ctypes.create_string_buffer(struct.pack("@HP", len(prog), ctypes.addressof(raw)))
    _check(_call(libc.prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog, 0, 0), "seccomp")


def _probe_child(arch: Arch) -> str:
    # 0048, issue 86: "" only when the probe socket() answers EPERM; an install error is reported.
    try:
        libc = _libc()
        _no_new_privs(libc)
        _install_filter(libc, arch)
    except OSError as exc:
        return f"seccomp probe: {exc}"
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
    except OSError as exc:
        return "" if exc.errno == errno.EPERM else f"seccomp probe: {exc}"
    return "seccomp probe: an AF_INET socket opened under the filter"


def _seccomp_probe(arch: Arch) -> str | None:
    # 0048, issue 86: a child applies the filter and reports through a pipe; None proves the filter.
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(read_fd)
            os.write(write_fd, _probe_child(arch).encode())
            code = 0
        finally:
            os._exit(code)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as pipe:
        text = pipe.read().decode(errors="replace")
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        return f"seccomp probe: the probe child exited with status {code}"
    return text or None


@lru_cache(maxsize=1)
def kernel_support() -> Support:
    # 0048, issue 86: the doctor and the confine check read this one answer; a probe error is kept.
    machine = platform.machine()
    if not sys.platform.startswith("linux") or machine not in ARCHES:
        return Support(None, 0, False)
    try:
        abi = landlock_abi()
    except OSError as exc:
        return Support(machine, 0, False, f"landlock probe: {exc}")
    if abi < 1:
        return Support(machine, 0, False)
    try:
        failure = _seccomp_probe(ARCHES[machine])
    except OSError as exc:
        failure = f"seccomp probe: {exc}"
    return Support(machine, abi, failure is None, failure or "")


def unusable(support: Support) -> str | None:
    # 0048, issue 86: None when the rules hold, else the cause and its Next line; no step-aside.
    if support.ok:
        return None
    if support.arch is None:
        where = f"{sys.platform} on {platform.machine() or 'an unknown architecture'}"
        return f"{where} has no modelled syscall table; {KERNEL_NEED}. {NEXT_KERNEL}"
    if support.abi < 1 and not support.error:
        return f"this kernel serves no Landlock ABI; {KERNEL_NEED}. {NEXT_KERNEL}"
    error = support.error or "the seccomp filter is not proven"
    return f"the kernel rules probe failed: {error}; {KERNEL_NEED}. {NEXT_PROBE}"


def _private_tmp(unit: str) -> str:
    # 0048: one folder per worktree, owned by this user, mode 0700, never a link.
    base = os.path.join(tempfile.gettempdir(), f"daedalus-confine-{os.getuid()}")
    folder = os.path.join(base, hashlib.sha256(unit.encode()).hexdigest()[:16])
    for path in (base, folder):
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refusal(
                f"{path} is not a private folder of this user. "
                "Next: remove that folder from your own shell, then rerun the command."
            )
    return folder


def _unit(given: str) -> tuple[str, str]:
    # 0048: --unit is a folder at <repo>/.claude/worktrees/<name>; returns it and the repo.
    real = os.path.realpath(given)
    if not os.path.isabs(given) or not os.path.isdir(real):
        raise Refusal(f"--unit {given} is not an absolute folder. {NEXT_FORM}")
    repo = os.path.realpath(project_root(Path(real)))
    if os.path.dirname(real) != os.path.join(repo, UNIT_WORKTREES):
        raise Refusal(f"--unit {given} is not a unit worktree of {repo}. {NEXT_FORM}")
    return real, repo


def _repo_entries(repo: str) -> list[str]:
    # 0048: the repo minus its data folder and the worktrees; a link is never followed.
    dot = os.path.join(repo, ".claude")
    skip = {dot, *(os.path.join(repo, h) for h in HIDDEN)}
    out: list[str] = []
    for folder in (repo, dot):
        if os.path.islink(folder) or not os.path.isdir(folder):
            continue
        with os.scandir(folder) as entries:
            out += sorted(e.path for e in entries if e.path not in skip and not e.is_symlink())
    return out


def _interpreter_paths() -> list[str]:
    found = [sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix]
    found.append(os.path.dirname(os.path.realpath(sys.executable)))
    found += [*site.getsitepackages(), site.getusersitepackages()]
    return found


def read_roots(repo: str, command: list[str]) -> tuple[str, ...]:
    # 0164: the operator config's wrapper_read_roots, for a runner row only; a bad config refuses.
    if not shell.runner_row(command):
        return ()
    try:
        return load_config(cwd=repo).wrapper_read_roots
    except (ConfigError, OSError, RuntimeError) as exc:
        raise Refusal(f"the operator config could not be read ({exc}). {NEXT_PROBE}") from exc


def rule_set(
    unit: str, repo: str, tmp: str, support: Support, extra: tuple[str, ...] = ()
) -> RuleSet:
    assert support.arch is not None
    stores = credential_roots()
    ro: list[str] = []
    for path in [*_interpreter_paths(), *SYSTEM_RO, *extra]:
        real = os.path.realpath(path)
        # 0048, Plan 6 section 10.1: no grant holds a credential store or sits inside one.
        if any(shell._under(real, s) or shell._under(s, real) for s in stores):
            continue
        if os.path.exists(real) and real not in ro:
            ro.append(real)
    return RuleSet(support.abi, support.arch, repo, (unit, tmp, *DEVICES_RW), tuple(ro), tmp)


def _add_rule(libc: ctypes.CDLL, ruleset: int, path: str, rights: int, follow: bool) -> None:
    flags = os.O_PATH | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            rights &= FILE_RIGHTS
        # linux/landlock.h:77-93: struct landlock_path_beneath_attr is packed, u64 then s32.
        attr = ctypes.create_string_buffer(struct.pack("=Qi", rights, fd))
        _check(_call(libc.syscall, NR_ADD_RULE, ruleset, RULE_PATH_BENEATH, attr, 0), path)
    finally:
        os.close(fd)


def apply(rules: RuleSet) -> None:
    # 0048, Plan 6 section 10.1: no_new_privs, the Landlock rule set, then the seccomp filter.
    libc = _libc()
    handled = FS_BY_ABI[min(rules.abi, 3)]
    net = NET_TCP if rules.abi >= NET_ABI else 0
    # linux/landlock.h:20-40: struct landlock_ruleset_attr; the net field exists from ABI 4.
    attr = struct.pack("=QQ", handled, net) if net else struct.pack("=Q", handled)
    buf = ctypes.create_string_buffer(attr)
    _no_new_privs(libc)
    ruleset = _check(_call(libc.syscall, NR_CREATE_RULESET, buf, len(attr), 0), "landlock ruleset")
    try:
        for path in rules.rw:
            _add_rule(libc, ruleset, path, handled, follow=path in DEVICES_RW)
        for path in [*_repo_entries(rules.repo), *rules.ro]:
            _add_rule(libc, ruleset, path, READ_ONLY & handled, follow=path in rules.ro)
        _check(_call(libc.syscall, NR_RESTRICT_SELF, ruleset, 0), "landlock restrict")
    finally:
        os.close(ruleset)
    _install_filter(libc, ARCHES[rules.arch])


def _tool_env(tmp: str) -> dict[str, str]:
    # 0048: an empty git config written fresh each run and an empty config home, both in tmp.
    config = os.path.join(tmp, GIT_CONFIG)
    os.close(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600))
    xdg = os.path.join(tmp, XDG_CONFIG)
    try:
        os.mkdir(xdg, 0o700)
    except FileExistsError:
        pass
    return {"TMPDIR": tmp, "GIT_CONFIG_GLOBAL": config, "XDG_CONFIG_HOME": xdg}


def _refuse(text: str) -> int:
    print(f"daedalus_confine: {text}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    split = confine_split([CONFINE, *argv])
    if split is None:
        return _refuse(f"usage: {CONFINE} --unit <worktree> -- <command...>. {NEXT_FORM}")
    support = kernel_support()
    cause = unusable(support)
    if cause is not None:
        return _refuse(cause)
    try:
        unit, repo = _unit(split[0])
        extra = read_roots(repo, split[1])
        rules = rule_set(unit, repo, _private_tmp(unit), support, extra)
        apply(rules)
    except Refusal as exc:
        return _refuse(str(exc))
    except OSError as exc:
        return _refuse(f"the kernel refused a rule ({exc}); {KERNEL_NEED}. {NEXT_PROBE}")
    os.environ.update(_tool_env(rules.tmp))
    print(rules.line(), flush=True)
    command = split[1]
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        print(f"daedalus_confine: cannot run {command[0]}: {exc.strerror}", file=sys.stderr)
    return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
