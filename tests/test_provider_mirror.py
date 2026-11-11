# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0256, issue 200: the run fetches Terraform providers outside the wrapper into a private mirror,
# and the kernel wrapper grants that one folder read-only with a mirror-only CLI config.
from __future__ import annotations

import errno
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

import daedalus_confine
import daedalus_train
import pytest
from lib import provider_mirror, shell, storage, train_state
from lib.provider_mirror import Grant

from tests.conftest import CFG, CWD, REPO_ROOT, git, write_train_marker
from tests.hook_chain import decide
from tests.payloads import _b

TRAIN = "20261111-120000"
ON = daedalus_confine.Support("x86_64", 3, True)
LIVE = daedalus_confine.kernel_support()
needs_kernel = pytest.mark.skipif(not LIVE.ok, reason="this kernel cannot hold the rules")
PROVIDERS = f"python3 {REPO_ROOT / 'scripts'}/daedalus_train.py providers --repo {CWD}"
TF = 'terraform {\n  required_providers {\n    null = {\n      source = "hashicorp/null"\n    }\n  }\n}\n'
PINNED = (
    "provider_installation {\n"
    "  filesystem_mirror {\n"
    '    path = "{mirror}"\n'
    "  }\n"
    "  direct {\n"
    '    exclude = ["*/*/*"]\n'
    "  }\n"
    "}\n"
)
# 0256: a stand-in terraform; its mode file picks ok, fail or hang, and each call is logged.
STAND_IN = "\n".join(
    [
        "import json, os, pathlib, subprocess, sys, time",
        "here = pathlib.Path(__file__).resolve().parent",
        'mode = (here / "mode").read_text().strip()',
        'with open(here / "calls.jsonl", "a", encoding="utf-8") as log:',
        '    call = {"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ)}',
        '    log.write(json.dumps(call) + "\\n")',
        'if mode == "ok":',
        '    pathlib.Path(sys.argv[-1], "fetched").write_text("x")',
        "    sys.exit(0)",
        'if mode == "hang":',
        '    subprocess.Popen(["sleep", "60"])',
        "    time.sleep(60)",
        'error = (here / "error").read_text()',
        'sys.stderr.write("\\n- Mirroring...\\nError: " + error + "\\nmore\\n")',
        "sys.exit(1)",
        "",
    ]
)
# 184: static code printing each environment entry on a line, as on branch infra/ci-workflow;
# a copied system tool is not used because a multi-call coreutils picks its tool by name.
ELF_CODE = {
    "x86_64": (
        0x3E,
        "488b0424488d5cc410488b334885f6742631d2803c1600740548ffc2ebf5c604160a48ffc2b801000000"
        "bf010000000f054883c308ebd2b83c00000031ff0f05",
    ),
    "aarch64": (
        0xB7,
        "e00340f9e16f208b33400091610240f9c10100b4020080d2236862386300003442040091fdffff1743018052"
        "2368223842040091200080d2080880d2010000d473220091f2ffff17000080d2a80b80d2010000d4",
    ),
}


def _elf() -> bytes:
    machine, text = ELF_CODE.get(platform.machine(), ELF_CODE["x86_64"])
    code, base = bytes.fromhex(text), 0x400000
    size = 64 + 56 + len(code)
    head = struct.pack(
        "<4sBBBB8xHHIQQQIHHHHHH",
        *(b"\x7fELF", 2, 1, 1, 0, 2, machine, 1, base + 120, 64, 0, 0, 64, 56, 1, 0, 0, 0),
    )
    return head + struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, size, size, 0x1000) + code


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "tr"
    monkeypatch.setattr(storage, "TMP_ROOT", root)
    return root


def _project(tmp_path: Path, checks: dict[str, object] | None = None) -> Path:
    repo = (tmp_path / "proj").resolve()
    (repo / "infra").mkdir(parents=True)
    (repo / "infra" / "main.tf").write_text(TF, encoding="utf-8")
    manifest = {"checks": {"terraform_validate": True} if checks is None else checks}
    (repo / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (repo / ".gitignore").write_text(".claude/\n", encoding="utf-8")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "i")
    write_train_marker(repo, TRAIN)
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "repo": str(repo)})
    return repo


def _stand_in(folder: Path, mode: str = "ok", error: str = "Provider not available") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    tool = folder / "terraform"
    tool.write_text(f"#!{sys.executable} -I\n{STAND_IN}", encoding="utf-8")
    tool.chmod(0o755)
    (folder / "mode").write_text(mode, encoding="utf-8")
    (folder / "error").write_text(error, encoding="utf-8")
    return tool


def _calls(folder: Path) -> list[dict[str, object]]:
    log = folder / "calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _run_train(repo: Path, monkeypatch: pytest.MonkeyPatch, bin_dir: Path) -> tuple[int, str]:
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    code = daedalus_train.main(["providers", "--repo", str(repo)])
    return code, ""


def _mirror(repo: Path) -> Path:
    return Path(os.path.realpath(provider_mirror.mirror_folder(repo, TRAIN)))


@pytest.mark.parametrize(
    "checks",
    [
        {"terraform_validate": False},
        {},
        {"terraform_validate": True, "terraform_format": False},
    ],
)
def test_the_fetch_runs_only_when_validate_is_on(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    checks: dict[str, object],
) -> None:
    repo = _project(tmp_path, checks)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, _ = _run_train(repo, monkeypatch, bin_dir)
    out = capsys.readouterr().out
    assert code == 0 and "skipped; the Terraform validate check is off" in out
    assert _calls(bin_dir) == [] and not tmp_root.exists()


def test_the_fetch_stops_with_a_next_line_when_no_run_is_marked(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _project(tmp_path)
    (repo / ".claude" / "daedalus" / "train.active").unlink()
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, _ = _run_train(repo, monkeypatch, bin_dir)
    out = capsys.readouterr().out.strip()
    assert code == 1 and out == provider_mirror.R_PROVIDERS_NO_RUN.format(root=repo)
    assert "Next:" in out and _calls(bin_dir) == []


def test_a_fetch_mirrors_each_root_and_records_it_without_touching_the_project(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _project(tmp_path)
    before = git(repo, "status", "--porcelain", "--ignored").stdout
    bin_dir = tmp_path / "bin"
    tool = _stand_in(bin_dir)
    code, _ = _run_train(repo, monkeypatch, bin_dir)
    assert code == 0
    assert capsys.readouterr().out.strip() == "providers: infra: fetched into the run's mirror."
    mirror = _mirror(repo)
    [call] = _calls(bin_dir)
    assert call["argv"] == [str(tool.resolve()), "providers", "mirror", "-no-color", str(mirror)]
    assert call["cwd"] == str(repo / "infra") and (mirror / "fetched").is_file()
    record = train_state.load(repo, TRAIN)[provider_mirror.STATE_KEY]
    assert record == {"roots": [{"folder": "infra", "result": "ok"}]}
    assert git(repo, "status", "--porcelain", "--ignored").stdout == before
    assert not any(p.name == "fetched" for p in repo.rglob("*"))
    for folder in (mirror.parent, mirror, mirror.parent / provider_mirror.DATA):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700


@pytest.mark.parametrize("name", ["a b", "-rf", "$(touch pwned);`id`", "-chdir=x"])
def test_a_root_folder_name_cannot_change_the_command(
    tmp_path: Path, tmp_root: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    # 0256: the folder is the working directory, never an argument; argv is a list, no shell.
    repo = _project(tmp_path)
    (repo / "infra").rename(repo / name)
    bin_dir = tmp_path / "bin"
    tool = _stand_in(bin_dir)
    lines = provider_mirror.fetch(str(repo), TRAIN, (), {"PATH": str(bin_dir)})
    mirror = _mirror(repo)
    assert lines == [f"providers: {name}: fetched into the run's mirror."]
    [call] = _calls(bin_dir)
    assert call["argv"] == [str(tool.resolve()), "providers", "mirror", "-no-color", str(mirror)]
    assert call["cwd"] == str(repo / name)
    assert not list(tmp_path.rglob("pwned"))


def test_a_root_reached_through_a_link_or_outside_the_checkout_is_skipped(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo = _project(tmp_path)
    (repo / "infra" / "main.tf").write_text("# no providers\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf").write_text(TF, encoding="utf-8")
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    (repo / "infra" / "providers.tf").symlink_to(outside / "main.tf")
    roots, unread = provider_mirror.find_roots(str(repo))
    assert roots == [] and unread == []


def test_skipped_and_excluded_folders_are_never_roots(
    tmp_path: Path, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _project(tmp_path)
    for rel in (".terraform/modules/m", ".claude/worktrees/u1/infra", ".git/x", "private/infra"):
        (repo / rel).mkdir(parents=True, exist_ok=True)
        (repo / rel / "main.tf").write_text(TF, encoding="utf-8")
    config = repo / ".claude" / "daedalus" / "config.json"
    entry = {"kind": "path", "path": "<repo_root>/private/"}
    config.write_text(json.dumps({"git_excluded_folders": [entry]}), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    assert daedalus_train.main(["providers", "--repo", str(repo)]) == 0
    assert [c["cwd"] for c in _calls(bin_dir)] == [str(repo / "infra")]


def test_a_provider_block_or_required_providers_makes_a_root_and_bad_hcl_is_named(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo = _project(tmp_path)
    (repo / "p").mkdir()
    (repo / "p" / "x.tf").write_text('provider "aws" {\n  region = "us-east-1"\n}\n')
    (repo / "plain").mkdir()
    (repo / "plain" / "x.tf").write_text('resource "null_resource" "a" {}\n')
    (repo / "broken").mkdir()
    (repo / "broken" / "x.tf").write_text("terraform {\n")
    roots, unread = provider_mirror.find_roots(str(repo))
    assert roots == [str(repo / "infra"), str(repo / "p")]
    assert unread == [str(repo / "broken" / "x.tf")]


def test_a_failing_terraform_warns_records_and_does_not_stop_the_run(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "fail")
    code, _ = _run_train(repo, monkeypatch, bin_dir)
    out = capsys.readouterr().out.strip()
    assert code == 0
    assert out.startswith(
        "warning: providers: infra: not fetched (Error: Provider not available). Next: "
    )
    record = train_state.load(repo, TRAIN)[provider_mirror.STATE_KEY]
    assert record == {
        "roots": [{"folder": "infra", "result": "failed", "error": "Error: Provider not available"}]
    }


def test_a_hanging_terraform_is_killed_with_its_children_and_recorded(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "hang")
    began = time.monotonic()
    lines = provider_mirror.fetch(str(repo), TRAIN, (), {"PATH": f"{bin_dir}:/usr/bin:/bin"}, 2)
    assert time.monotonic() - began < 20
    assert lines[0].startswith("warning: providers: infra: not fetched (Error: terraform did not")
    record = train_state.load(repo, TRAIN)[provider_mirror.STATE_KEY]
    assert record["roots"][0]["result"] == "failed"


def test_the_environment_is_reduced_and_never_echoed(tmp_path: Path, tmp_root: Path) -> None:
    # 0256: a caller secret reaches terraform only by an allowed name and never the record.
    repo = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    token, password = "tok-SECRET-1234", "pw-SECRET-5678"
    _stand_in(bin_dir, "fail", f"auth {token} via user:{password}@proxy failed")
    source = {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path / "home"),
        "TF_TOKEN_registry_example_com": token,
        "HTTPS_PROXY": f"http://user:{password}@proxy:3128",
        "AWS_SECRET_ACCESS_KEY": "aws-SECRET-9999",
        "TF_CLI_ARGS": "-chdir=/etc",
        "TF_CLI_ARGS_providers_mirror": "-platform=x",
        "TF_LOG": "trace",
        "TF_LOG_PATH": str(repo / "log.txt"),
        "TF_PLUGIN_CACHE_DIR": str(repo / "cache"),
        "TF_DATA_DIR": str(repo / ".terraform"),
    }
    lines = provider_mirror.fetch(str(repo), TRAIN, (), source)
    [call] = _calls(bin_dir)
    env = call["env"]
    assert isinstance(env, dict)
    passed = {"PATH", "HOME", "TF_TOKEN_registry_example_com", "HTTPS_PROXY"}
    # PEP 538: the stand-in's own interpreter adds LC_CTYPE when it coerces the C locale.
    assert set(env) - {"LC_CTYPE"} == passed | set(provider_mirror.FIXED_ENV) | {"TF_DATA_DIR"}
    assert env["TF_DATA_DIR"] == str(_mirror(repo).parent / provider_mirror.DATA)
    state = (repo / ".claude" / "daedalus" / "trains" / f"{TRAIN}.json").read_text()
    for text in (state, "\n".join(lines)):
        assert "SECRET" not in text and provider_mirror.WITHHELD in text
    assert not (repo / "log.txt").exists() and not (repo / "cache").exists()


def test_a_terraform_inside_the_project_or_off_path_is_never_run(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo = _project(tmp_path)
    planted = repo / "tools"
    _stand_in(planted)
    lines = provider_mirror.fetch(str(repo), TRAIN, (), {"PATH": str(planted)})
    assert _calls(planted) == []
    assert lines[0].startswith("warning: providers: no terraform outside the project is on PATH")
    assert "Next:" in lines[0]
    rel = provider_mirror.fetch(str(repo), TRAIN, (), {})
    assert rel == lines


def _grant_line(repo: Path, unit: Path, mirror: Grant) -> str:
    rules = daedalus_confine.rule_set(str(unit), str(repo), "/t", ON, (), None, mirror)
    return rules.line()


def test_the_mirror_is_granted_alone_and_named_in_the_read_only_list(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo = _project(tmp_path)
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    provider_mirror.make_mirror(repo, TRAIN)
    mirror = _mirror(repo)
    grant = provider_mirror.granted_mirror(str(repo))
    assert grant == Grant(path=str(mirror))
    rules = daedalus_confine.rule_set(str(unit), str(repo), "/t", ON, (), None, grant)
    assert rules.mirror == str(mirror) and str(mirror) not in rules.ro
    assert not any(shell._under(str(mirror.parent), r) for r in rules.ro)
    line = rules.line()
    plain = daedalus_confine.rule_set(str(unit), str(repo), "/t", ON).line()
    assert (
        line == plain.replace(" refused=", f",{mirror} refused=") + " tf_cli_config=/t/terraformrc"
    )


def _break(case: str, repo: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    # 0256: one way per case that the mirror stops being this run's private folder.
    mirror = provider_mirror.mirror_folder(repo, TRAIN)
    if case == "link":
        other = repo.parent / "elsewhere"
        other.mkdir()
        shutil.rmtree(mirror)
        mirror.symlink_to(other, target_is_directory=True)
        return "is a symlink"
    if case == "run link":
        other = repo.parent / "other-run"
        (other / provider_mirror.MIRROR).mkdir(parents=True, mode=0o700)
        other.chmod(0o700)
        shutil.rmtree(mirror.parent)
        mirror.parent.symlink_to(other, target_is_directory=True)
        return "is a symlink"
    if case == "file":
        shutil.rmtree(mirror)
        mirror.write_text("x", encoding="utf-8")
        return "is not a folder"
    if case in ("group", "world"):
        mirror.chmod(0o770 if case == "group" else 0o702)
        return "can be written by group or others"
    if case == "owner":
        real = Path.lstat

        def foreign(self: Path) -> os.stat_result:
            info = real(self)
            if self != mirror:
                return info
            fields = list(info)
            fields[4] = info.st_uid + 1
            return os.stat_result(fields)

        monkeypatch.setattr(Path, "lstat", foreign)
        return "is not owned by you"
    raise AssertionError(case)


@pytest.mark.parametrize("case", ["link", "run link", "file", "group", "world", "owner"])
def test_a_bad_mirror_folder_is_not_granted_and_the_line_says_so(
    tmp_path: Path, tmp_root: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    repo = _project(tmp_path)
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    provider_mirror.make_mirror(repo, TRAIN)
    words = _break(case, repo, monkeypatch)
    grant = provider_mirror.granted_mirror(str(repo))
    assert grant.path == "" and words in grant.reason and "Next:" in grant.reason
    run = provider_mirror.run_folder(repo, TRAIN)
    line = _grant_line(repo, unit, grant)
    assert line.endswith(f" tf_mirror={grant.reason}") and "tf_cli_config" not in line
    assert str(run) not in line.split(" tf_mirror=")[0]
    assert grant.reason.startswith("not granted: ") and grant.reason.endswith(
        "then rerun daedalus_train.py providers from the main session."
    )


def test_a_mirror_that_resolves_elsewhere_is_not_granted(
    tmp_path: Path, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0256: reachable through a bind mount or a race after the link checks; the path must match.
    repo = _project(tmp_path)
    provider_mirror.make_mirror(repo, TRAIN)
    mirror = str(provider_mirror.mirror_folder(repo, TRAIN))
    real = provider_mirror._resolved
    monkeypatch.setattr(
        provider_mirror, "_resolved", lambda p: "/home/x/.ssh" if p == mirror else real(p)
    )
    grant = provider_mirror.granted_mirror(str(repo))
    want = provider_mirror.R_MIRROR_OUTSIDE.format(path=mirror)
    assert grant.path == "" and want in grant.reason


def test_a_mirror_inside_a_credential_store_is_not_granted(
    tmp_path: Path, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _project(tmp_path)
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    provider_mirror.make_mirror(repo, TRAIN)
    grant = provider_mirror.granted_mirror(str(repo))
    monkeypatch.setattr(daedalus_confine, "credential_roots", lambda: [str(tmp_root)])
    rules = daedalus_confine.rule_set(str(unit), str(repo), "/t", ON, (), None, grant)
    assert rules.mirror == ""
    assert rules.mirror_refused == daedalus_confine.R_MIRROR_STORE.format(path=grant.path)


@pytest.mark.parametrize("marker", [None, "../../etc", f"{TRAIN}x", "20261111-130000"])
def test_no_marked_run_or_another_runs_mirror_grants_nothing(
    tmp_path: Path, tmp_root: Path, marker: str | None
) -> None:
    repo = _project(tmp_path)
    provider_mirror.make_mirror(repo, TRAIN)
    path = repo / ".claude" / "daedalus" / "train.active"
    if marker is None:
        path.unlink()
    else:
        path.write_text(f"{marker}\n{TRAIN}\n", encoding="utf-8")
    assert provider_mirror.granted_mirror(str(repo)) == Grant()


def test_the_cli_config_holds_exactly_the_pinned_block(tmp_path: Path) -> None:
    tmp = tmp_path / "t"
    tmp.mkdir(mode=0o700)
    mirror = "/tmp/.daedalus/1000/provider-mirror/0123456789abcdef/20261111-120000/mirror"
    env = daedalus_confine._tool_env(str(tmp), ["terraform", "validate"], mirror)
    config = Path(env["TF_CLI_CONFIG_FILE"])
    assert config == tmp / daedalus_confine.TF_CLI_CONFIG
    assert config.read_text(encoding="utf-8") == PINNED.replace("{mirror}", mirror)
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert "TF_CLI_CONFIG_FILE" not in daedalus_confine._tool_env(str(tmp), ["make", "test"])


def test_a_mirror_path_with_quote_or_brace_characters_is_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0256: a TMP_ROOT holding a quote would break out of the HCL string; it is not granted.
    root = tmp_path / 'tr"}\nprovider_installation {'
    monkeypatch.setattr(storage, "TMP_ROOT", root)
    repo = _project(tmp_path)
    with pytest.raises(RuntimeError, match="resolves outside the run's temporary folder"):
        provider_mirror.make_mirror(repo, TRAIN)
    grant = provider_mirror.granted_mirror(str(repo))
    assert grant.path == "" and "resolves outside the run's temporary folder" in grant.reason
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    lines = provider_mirror.fetch(str(repo), TRAIN, (), {"PATH": str(bin_dir)})
    assert lines[0].startswith("warning: providers: the mirror folder could not be made (")
    assert _calls(bin_dir) == []


def test_the_wrapper_points_terraform_at_the_config_in_its_private_tmp(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 0256: kernel independent; the rules are not applied and the exec is caught.
    repo = _project(tmp_path)
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    provider_mirror.make_mirror(repo, TRAIN)
    names = ("TMPDIR", "GIT_CONFIG_GLOBAL", "XDG_CONFIG_HOME", "TF_DATA_DIR", "TF_CLI_CONFIG_FILE")
    for name in names:
        monkeypatch.setenv(name, "x")
        monkeypatch.delenv(name)
    monkeypatch.setenv("TF_PLUGIN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: ON)
    monkeypatch.setattr(daedalus_confine, "apply", lambda rules: None)
    monkeypatch.setattr(daedalus_confine, "terraform_binary", lambda *a: None)
    seen: dict[str, str] = {}

    def caught(file: str, args: list[str]) -> None:
        seen.update(os.environ)
        raise OSError(2, "caught")

    monkeypatch.setattr(daedalus_confine.os, "execvp", caught)
    init = ["terraform", f"-chdir={unit}", *shell.TERRAFORM_INIT]
    assert daedalus_confine.main(["--unit", str(unit), "--", *init]) == 127
    tmp = daedalus_confine._private_tmp(str(unit.resolve()))
    assert seen["TF_CLI_CONFIG_FILE"] == os.path.join(tmp, daedalus_confine.TF_CLI_CONFIG)
    assert "TF_PLUGIN_CACHE_DIR" not in seen
    config = Path(seen["TF_CLI_CONFIG_FILE"]).read_text(encoding="utf-8")
    assert config == PINNED.replace("{mirror}", str(_mirror(repo)))
    first = capsys.readouterr().out.splitlines()[0]
    assert f",{_mirror(repo)} refused=" in first and first.endswith(
        f"tf_cli_config={tmp}/terraformrc"
    )


@pytest.fixture
def real_mirror(tmp_path: Path) -> tuple[Path, Path]:
    # 0256: the subprocess reads the real TMP_ROOT; the project-key folder is removed after.
    repo = _project(tmp_path)
    unit = repo / ".claude" / "worktrees" / "u1"
    unit.mkdir(parents=True)
    provider_mirror.make_mirror(repo, TRAIN)
    yield repo, unit.resolve()
    shutil.rmtree(storage.tmp_dir(provider_mirror.FEATURE, repo), ignore_errors=True)


@needs_kernel
def test_a_wrapped_init_sees_the_cli_config_and_the_first_line_names_the_mirror(
    tmp_path: Path, real_mirror: tuple[Path, Path]
) -> None:
    repo, unit = real_mirror
    real = tmp_path / "home" / "opt" / "terraform"
    real.parent.mkdir(parents=True)
    real.write_bytes(_elf())
    real.chmod(0o755)
    argv = [sys.executable, str(shell.CONFINE_PATH), "--unit", str(unit), "--", "terraform"]
    argv += [f"-chdir={unit}", *shell.TERRAFORM_INIT]
    env = {**os.environ, "PATH": f"{real.parent}:/usr/bin:/bin", "TF_CLI_CONFIG_FILE": "/etc/x"}
    done = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=unit, env=env)
    assert done.returncode == 0, done.stderr
    tmp = daedalus_confine._private_tmp(str(unit))
    seen = [line for line in done.stdout.splitlines() if line.startswith("TF_CLI_CONFIG_FILE=")]
    assert seen == [f"TF_CLI_CONFIG_FILE={tmp}/terraformrc"]
    support = LIVE
    grant = provider_mirror.granted_mirror(str(repo))
    rules = daedalus_confine.rule_set(
        str(unit), str(repo), tmp, support, (), str(real.resolve()), grant
    )
    first = done.stdout.splitlines()[0]
    assert first == rules.line() and f",{grant.path} refused=" in first
    # 0048: Landlock TCP rules join from ABI 4; the seccomp socket refusal never drops.
    net = "landlock-tcp," if support.abi >= daedalus_confine.NET_ABI else ""
    assert f"refused={net}socket(AF_INET,AF_INET6,AF_UNIX,any family but AF_NETLINK)" in first


@needs_kernel
def test_a_coder_still_cannot_open_a_socket_or_write_the_mirror(
    real_mirror: tuple[Path, Path],
) -> None:
    repo, unit = real_mirror
    mirror = provider_mirror.granted_mirror(str(repo)).path
    assert mirror
    code = (
        "import socket, os\n"
        "for fam in (socket.AF_INET, socket.AF_UNIX):\n"
        "    try:\n"
        "        socket.socket(fam, socket.SOCK_STREAM)\n"
        "        print('opened')\n"
        "    except OSError as e:\n"
        "        print('refused', e.errno)\n"
        f"print(sorted(os.listdir({mirror!r})))\n"
        "try:\n"
        f"    open(os.path.join({mirror!r}, 'w'), 'w')\n"
        "    print('wrote')\n"
        "except OSError as e:\n"
        "    print('nowrite', e.errno)\n"
        "try:\n"
        f"    os.listdir(os.path.dirname({mirror!r}))\n"
        "    print('parent')\n"
        "except OSError as e:\n"
        "    print('noparent', e.errno)\n"
    )
    argv = [sys.executable, str(shell.CONFINE_PATH), "--unit", str(unit), "--"]
    argv += [sys.executable, "-c", code]
    done = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=unit)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()[1:]
    assert lines[:2] == [f"refused {errno.EPERM}", f"refused {errno.EPERM}"]
    assert lines[2] == "[]" and lines[3].startswith("nowrite") and lines[4].startswith("noparent")


@pytest.mark.usefixtures("jail_fakes")
def test_the_orchestrator_runs_the_fetch_and_no_other_agent_or_prefix_does() -> None:
    assert decide(_b("orchestrator", PROVIDERS), CFG).allow
    for agent in ("coder", "auditor", "verifier", "releaser", "charter-docs"):
        assert not decide(_b(agent, PROVIDERS), CFG).allow, agent
    for prefix in ("TF_CLI_ARGS=-chdir=/etc ", "PATH=/tmp/x ", "env PATH=/tmp/x "):
        assert not decide(_b("orchestrator", prefix + PROVIDERS), CFG).allow, prefix
