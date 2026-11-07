# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 184: a terraform found only in a home bin folder enters the wrapper's rules as one file.
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import daedalus_confine
import pytest
from lib import shell

from tests.test_confine import ON, _unit

FAKE = '#!/bin/sh\necho "tf_data=$TF_DATA_DIR args=$*"\n'


def _home_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    # 184: a fake terraform the session PATH names, behind a link as tfenv and asdf leave it.
    real = tmp_path / "home" / ".tfenv" / "versions" / "1.9.0" / "terraform"
    real.parent.mkdir(parents=True)
    real.write_text(FAKE, encoding="utf-8")
    real.chmod(0o755)
    folder = tmp_path / "home" / ".local" / "bin"
    folder.mkdir(parents=True)
    (folder / "terraform").symlink_to(real)
    monkeypatch.setenv("PATH", str(folder))
    return folder, real.resolve()


def test_a_home_bin_terraform_enters_the_rule_set_as_one_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder, real = _home_bin(tmp_path, monkeypatch)
    repo, unit = _unit(tmp_path)
    binary = daedalus_confine.terraform_binary(["terraform", "validate"], str(repo))
    assert binary == str(real)
    rules = daedalus_confine.rule_set(str(unit), str(repo), str(tmp_path / "t"), ON, (), binary)
    assert str(real) in rules.ro
    assert not any(shell._under(str(folder), r) or r == str(real.parent) for r in rules.ro)
    assert daedalus_confine.rule_set(str(unit), str(repo), str(tmp_path / "t"), ON).ro == tuple(
        r for r in rules.ro if r != str(real)
    )


@pytest.mark.parametrize("case", ["other command", "not found", "relative", "store", "claude"])
def test_no_grant_for_another_command_a_miss_a_relative_path_or_a_guarded_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    # 184: no grant leaves the rule set unchanged and the exec as execvp runs it today.
    folder, real = _home_bin(tmp_path, monkeypatch)
    repo, _ = _unit(tmp_path)
    command = ["make", "test"] if case == "other command" else ["terraform", "validate"]
    if case == "not found":
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    if case == "relative":
        monkeypatch.chdir(folder)
        monkeypatch.setenv("PATH", ".")
    if case == "store":
        monkeypatch.setattr(daedalus_confine, "credential_roots", lambda: [real.parent])
    if case == "claude":
        moved = repo / ".claude" / "bin" / "terraform"
        moved.parent.mkdir()
        moved.write_text(FAKE, encoding="utf-8")
        moved.chmod(0o755)
        monkeypatch.setenv("PATH", str(moved.parent))
    assert daedalus_confine.terraform_binary(command, str(repo)) is None


def _data(tmp: Path, module: Path) -> Path:
    digest = hashlib.sha256(os.path.realpath(module).encode()).hexdigest()[:16]
    return tmp / "tf-data" / digest


def test_tf_data_dir_lands_in_the_private_tmp_and_init_empties_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp, module = tmp_path / "t", tmp_path / "infra"
    tmp.mkdir(mode=0o700)
    module.mkdir()
    monkeypatch.setenv("TF_DATA_DIR", str(tmp_path / "caller"))
    validate = ["terraform", f"-chdir={module}", "validate"]
    env = daedalus_confine._tool_env(str(tmp), validate)
    assert env["TF_DATA_DIR"] == str(_data(tmp, module))
    leftover = _data(tmp, module) / "providers"
    leftover.mkdir()
    assert daedalus_confine._tool_env(str(tmp), validate)["TF_DATA_DIR"] == env["TF_DATA_DIR"]
    assert leftover.is_dir()
    init = ["terraform", f"-chdir={module}", *shell.TERRAFORM_INIT]
    assert daedalus_confine._tool_env(str(tmp), init)["TF_DATA_DIR"] == env["TF_DATA_DIR"]
    assert not leftover.exists() and _data(tmp, module).is_dir()
    assert "TF_DATA_DIR" not in daedalus_confine._tool_env(str(tmp), ["make", "test"])


@pytest.mark.skipif(
    not daedalus_confine.kernel_support().ok, reason="this kernel cannot hold the rules"
)
def test_the_wrapper_runs_a_home_bin_terraform_with_its_data_folder_in_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder, _ = _home_bin(tmp_path, monkeypatch)
    _, unit = _unit(tmp_path)
    argv = [sys.executable, str(shell.CONFINE_PATH), "--unit", str(unit), "--", "terraform"]
    argv += [f"-chdir={unit}", "validate"]
    env = {**os.environ, "PATH": f"{folder}:/usr/bin:/bin", "TF_DATA_DIR": "/elsewhere"}
    done = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=unit, env=env)
    assert done.returncode == 0, done.stderr
    tmp = Path(daedalus_confine._private_tmp(str(unit.resolve())))
    assert done.stdout.splitlines()[-1] == (
        f"tf_data={_data(tmp, unit)} args=-chdir={unit} validate"
    )
