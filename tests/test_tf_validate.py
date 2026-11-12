# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0265: the run validates a unit's Terraform outside the kernel wrapper on a staged copy of the
# unit tip read as git blobs, with providers from the run's mirror alone and no module download.
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import daedalus_train
import pytest
from lib import provider_mirror, storage, tf_validate, train_state

from tests.conftest import CFG, CWD, REPO_ROOT, git, write_train_marker
from tests.hook_chain import decide
from tests.payloads import _b

TRAIN = "20261111-130000"
UNIT = "u1"
BRANCH = f"daedalus-unit/{TRAIN}-{UNIT}"
NULL = (
    "terraform {\n  required_providers {\n"
    '    null = { source = "hashicorp/null", version = "3.2.3" }\n  }\n}\n'
)
VALIDATE = f"python3 {REPO_ROOT / 'scripts'}/daedalus_train.py validate --repo {CWD} --unit u1"
# 0265: a stand-in terraform; it logs each call with its staged files, then acts like terraform
# by starting any program under its folder's .terraform/providers, and answers by its mode file.
STAND_IN = "\n".join(
    [
        "import json, os, pathlib, subprocess, sys, time",
        "here = pathlib.Path(__file__).resolve().parent",
        'mode = (here / "mode").read_text().strip()',
        "cwd = pathlib.Path.cwd()",
        'stage = pathlib.Path(os.environ["TF_CLI_CONFIG_FILE"]).parent',
        "files = {}",
        'for p in sorted((stage / "tree").rglob("*")):',
        "    if p.is_symlink() or p.is_file():",
        '        rel = str(p.relative_to(stage / "tree"))',
        '        files[rel] = "LINK" if p.is_symlink() else p.read_text(errors="replace")',
        'manifest = pathlib.Path(os.environ["TF_DATA_DIR"], "modules", "modules.json")',
        'call = {"argv": sys.argv, "cwd": str(cwd), "env": dict(os.environ), "files": files,',
        '        "stage": str(stage), "rc": (stage / "terraformrc").read_text(),',
        '        "modules": manifest.read_text() if manifest.is_file() else None}',
        'with open(here / "calls.jsonl", "a", encoding="utf-8") as log:',
        '    log.write(json.dumps(call) + "\\n")',
        'planted = cwd / ".terraform" / "providers"',
        'for prog in sorted(planted.rglob("*")) if planted.exists() else []:',
        "    if prog.is_file() and os.access(prog, os.X_OK):",
        "        subprocess.run([str(prog)])",
        'if mode == "hang":',
        '    child = subprocess.Popen(["/bin/sleep", "60"])',
        '    (here / "child").write_text(str(child.pid))',
        "    time.sleep(60)",
        'if sys.argv[1] == "init":',
        '    if mode == "missing":',
        '        d = {"severity": "error", "summary": "Failed to query available provider '
        'packages", "detail": "x"}',
        '        print(json.dumps({"type": "diagnostic", "diagnostic": d}))',
        "        sys.exit(1)",
        '    if mode == "junk":',
        '        print("not json")',
        "        sys.exit(1)",
        '    print(json.dumps({"type": "version"}))',
        "    sys.exit(0)",
        'if mode == "fail":',
        '    print((here / "diags").read_text())',
        "    sys.exit(1)",
        'print(json.dumps({"valid": True, "error_count": 0, "diagnostics": []}))',
        "",
    ]
)


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "tr"
    monkeypatch.setattr(storage, "TMP_ROOT", root)
    return root


def _commit(where: Path, message: str = "c") -> str:
    git(where, "add", "-A")
    git(where, "commit", "-qm", message)
    return git(where, "rev-parse", "HEAD").stdout.strip()


def _project(tmp_path: Path, checks: dict[str, object] | None = None) -> tuple[Path, Path]:
    # 0265: base commit recorded as base_sha, one unit worktree on its own branch, a mirror.
    repo = (tmp_path / "proj").resolve()
    (repo / "infra").mkdir(parents=True)
    (repo / "infra" / "main.tf").write_text(NULL, encoding="utf-8")
    manifest = {"checks": {"terraform_validate": True} if checks is None else checks}
    (repo / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (repo / ".gitignore").write_text(".claude/\n", encoding="utf-8")
    git(repo, "init", "-q", "-b", "main")
    base = _commit(repo, "base")
    write_train_marker(repo, TRAIN)
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "repo": str(repo), "base_sha": base})
    unit = repo / ".claude" / "worktrees" / f"{TRAIN}-{UNIT}"
    git(repo, "worktree", "add", "-q", "-b", BRANCH, str(unit))
    train_state.add_unit(repo, TRAIN, f"{TRAIN}-{UNIT}", BRANCH, unit)
    return repo, unit


def _mirror(repo: Path, *addresses: str) -> Path:
    mirror = provider_mirror.make_mirror(str(repo), TRAIN)
    for address in addresses or ("registry.terraform.io/hashicorp/null",):
        (mirror / address).mkdir(parents=True)
    return mirror


def _stand_in(folder: Path, mode: str = "ok", diags: str = "") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    tool = folder / "terraform"
    tool.write_text(f"#!{sys.executable} -I\n{STAND_IN}", encoding="utf-8")
    tool.chmod(0o755)
    (folder / "mode").write_text(mode, encoding="utf-8")
    (folder / "diags").write_text(diags, encoding="utf-8")
    return tool


def _calls(folder: Path) -> list[dict[str, object]]:
    log = folder / "calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _run(
    repo: Path, monkeypatch: pytest.MonkeyPatch, bin_dir: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, list[str]]:
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    code = daedalus_train.main(["validate", "--repo", str(repo), "--unit", UNIT])
    return code, capsys.readouterr().out.splitlines()


def _status(repo: Path, unit: Path) -> tuple[str, str]:
    return (
        git(repo, "status", "--porcelain", "--ignored").stdout,
        git(unit, "status", "--porcelain", "--ignored").stdout,
    )


def _record(repo: Path) -> dict[str, object]:
    [unit] = train_state.units(train_state.load(repo, TRAIN))
    record = unit[tf_validate.STATE_KEY]
    assert isinstance(record, dict)
    return record


def _files(call: dict[str, object]) -> dict[str, str]:
    files = call["files"]
    assert isinstance(files, dict)
    return files


def _plant(unit: Path, marker: Path) -> None:
    # 0265, issue 118: a program where terraform looks for providers, in the unit's worktree.
    folder = unit / "infra" / ".terraform" / "providers" / "registry.terraform.io" / "hashicorp"
    folder = folder / "null" / "3.2.3" / "linux_amd64"
    folder.mkdir(parents=True)
    prog = folder / "terraform-provider-null_v3.2.3_x5"
    prog.write_text(
        f"#!{sys.executable} -I\nimport pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    prog.chmod(0o755)


def test_validate_stops_with_a_next_line_when_no_run_is_marked(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = _project(tmp_path)
    (repo / ".claude" / "daedalus" / "train.active").unlink()
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 1 and out == [tf_validate.R_VALIDATE_NO_RUN.format(root=repo)]
    assert "Next:" in out[0] and _calls(bin_dir) == []


@pytest.mark.parametrize(
    "checks",
    [{"terraform_validate": False}, {}, {"terraform_validate": True, "terraform_format": False}],
)
def test_validate_runs_only_when_the_check_is_on(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    checks: dict[str, object],
) -> None:
    repo, _ = _project(tmp_path, checks)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0
    assert out == ["validate: skipped; the Terraform validate check is off for this project."]
    assert _calls(bin_dir) == [] and not tmp_root.exists()


def test_an_unknown_unit_stops_with_a_next_line(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    code = daedalus_train.main(["validate", "--repo", str(repo), "--unit", "../../etc"])
    out = capsys.readouterr().out
    assert code == 1 and "records no worktree for unit ../../etc" in out and "Next:" in out
    assert _calls(bin_dir) == []


def test_a_clean_unit_validates_from_a_staged_copy_and_never_touches_the_project(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    mirror = _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + 'resource "null_resource" "a" {}\n')
    tip = _commit(unit, "unit")
    before = _status(repo, unit)
    bin_dir = tmp_path / "bin"
    tool = _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert (code, out) == (0, ["validate: infra: validated clean."])
    init, check = _calls(bin_dir)
    assert init["argv"] == [str(tool.resolve()), *tf_validate.INIT_ARGS]
    assert check["argv"] == [str(tool.resolve()), *tf_validate.VALIDATE_ARGS]
    assert "-get=false" in tf_validate.INIT_ARGS
    assert not any(a.startswith("-lockfile") for a in tf_validate.INIT_ARGS)
    stage = Path(str(init["stage"]))
    run_folder = storage.tmp_dir(tf_validate.FEATURE, repo) / TRAIN
    assert str(stage).startswith(os.path.realpath(run_folder) + os.sep)
    assert init["cwd"] == str(stage / "tree" / "infra")
    assert _files(init) == {"infra/main.tf": NULL + 'resource "null_resource" "a" {}\n'}
    assert init["rc"] == provider_mirror.cli_config(os.path.realpath(mirror))
    assert json.loads(str(init["modules"])) == {"Modules": [{"Key": "", "Source": "", "Dir": "."}]}
    assert _record(repo) == {
        "tip": tip,
        "roots": [{"folder": "infra", "result": "clean", "lines": out}],
    }
    assert _status(repo, unit) == before
    assert not stage.exists() and list(Path(os.path.realpath(run_folder)).iterdir()) == []
    assert stat.S_IMODE(Path(os.path.realpath(run_folder)).stat().st_mode) == 0o700


def test_a_planted_provider_and_project_config_in_the_worktree_are_never_copied_or_run(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # issue 118: neither the worktree on disk nor files committed beside the .tf reach terraform.
    repo, unit = _project(tmp_path)
    _mirror(repo)
    marker = tmp_path / "marker"
    _plant(unit, marker)
    infra = unit / "infra"
    (infra / "main.tf").write_text(NULL + "# changed\n", encoding="utf-8")
    (infra / ".terraformrc").write_text('plugin_cache_dir = "/tmp/x"\n', encoding="utf-8")
    (infra / "terraform.tfvars").write_text('x = "1"\n', encoding="utf-8")
    (infra / "prod.auto.tfvars").write_text('x = "1"\n', encoding="utf-8")
    (infra / "run.sh").write_text("touch pwned\n", encoding="utf-8")
    (infra / "main.tf.bak").write_text("x\n", encoding="utf-8")
    plugins = infra / "terraform.d" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "x.tf").write_text(NULL, encoding="utf-8")
    git(unit, "add", "-f", "-A")
    _commit(unit, "unit with planted files")
    _plant(unit / "untracked", marker)
    before = _status(repo, unit)
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0 and "validate: infra: validated clean." in out
    init = next(c for c in _calls(bin_dir) if str(c["cwd"]).endswith("/tree/infra"))
    assert _files(init) == {"infra/main.tf": NULL + "# changed\n"}
    assert not marker.exists() and not list(tmp_path.rglob("pwned"))
    assert _status(repo, unit) == before


def test_a_lock_with_other_platforms_hashes_is_staged_without_hashes(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 0265: a lock holding only another platform's hashes failed init; versions stay, hashes go.
    repo, unit = _project(tmp_path)
    _mirror(repo)
    lock = (
        'provider "registry.terraform.io/hashicorp/null" {\n'
        '  version     = "3.2.3"\n'
        '  constraints = "3.2.3"\n'
        "  hashes = [\n"
        '    "h1:I0Um8UkrMUb81Fxq/dxbr3HLP2cecTH2WMJiwKSrwQY=",\n'
        "  ]\n}\n"
        'provider "evil\\"host/x/y" {\n  version = "1.0.0"\n}\n'
        'provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.0.0\\"\\n}"\n}\n'
    )
    (unit / "infra" / provider_mirror.LOCK_FILE).write_text(lock, encoding="utf-8")
    _commit(unit, "lock")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, _ = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0
    staged = _files(_calls(bin_dir)[0])["infra/.terraform.lock.hcl"]
    assert staged == (
        'provider "registry.terraform.io/hashicorp/null" {\n'
        '  version = "3.2.3"\n'
        '  constraints = "3.2.3"\n'
        "}\n"
    )
    assert (unit / "infra" / provider_mirror.LOCK_FILE).read_text(encoding="utf-8") == lock


@pytest.mark.parametrize(
    ("source", "said"),
    [
        (
            "hashicorp/consul/aws",
            "comes from hashicorp/consul/aws, which the run does not download",
        ),
        ("git::https://example.com/m.git", "comes from git::https://example.com/m.git"),
        ("https://example.com/m.zip", "comes from https://example.com/m.zip"),
        ("/etc/terraform", "comes from /etc/terraform"),
        ("../../outside", "points at ../../outside, which leaves the repository"),
        ("./../../../outside", "points at ./../../../outside, which leaves the repository"),
        ("./.terraform/modules/m", "a folder the run does not stage"),
    ],
)
def test_a_module_from_anywhere_but_a_local_folder_is_never_fetched_and_its_root_is_named(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: str,
    said: str,
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "mod.tf").write_text(f'module "m" {{\n  source = "{source}"\n}}\n')
    _commit(unit, "module")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0 and _calls(bin_dir) == []
    [line] = out
    assert line.startswith("validate: infra: not validated, because module m ")
    assert said in line and "Next:" in line
    assert _record(repo)["roots"] == [{"folder": "infra", "result": "not validated", "lines": out}]


def test_a_local_module_is_staged_in_place_and_listed_so_init_downloads_nothing(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "modules" / "net" / "inner").mkdir(parents=True)
    (unit / "modules" / "net" / "main.tf").write_text(
        'module "deep" {\n  source = "./inner"\n}\n', encoding="utf-8"
    )
    (unit / "modules" / "net" / "inner" / "main.tf").write_text("# inner\n", encoding="utf-8")
    (unit / "modules" / "net" / "notes.md").write_text("x\n", encoding="utf-8")
    (unit / "infra" / "main.tf").write_text(
        NULL + 'module "net" {\n  source = "../modules/net"\n}\n', encoding="utf-8"
    )
    (unit / "infra" / "override.tf").write_text(
        'module "net" {\n  source = "./../modules/net"\n}\n', encoding="utf-8"
    )
    _commit(unit, "modules")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0
    assert "validate: infra: validated clean." in out
    init = next(c for c in _calls(bin_dir) if str(c["cwd"]).endswith("/tree/infra"))
    assert set(_files(init)) == {
        "infra/main.tf",
        "infra/override.tf",
        "modules/net/main.tf",
        "modules/net/inner/main.tf",
    }
    assert json.loads(str(init["modules"]))["Modules"] == [
        {"Key": "", "Source": "", "Dir": "."},
        {"Key": "net", "Source": "./../modules/net", "Dir": "../modules/net"},
        {"Key": "net.deep", "Source": "./inner", "Dir": "../modules/net/inner"},
    ]


def test_a_module_cycle_stops_at_the_depth_cap(tmp_path: Path, tmp_root: Path) -> None:
    repo, unit = _project(tmp_path)
    mirror = _mirror(repo)
    (unit / "infra" / "main.tf").write_text('module "self" {\n  source = "./"\n}\n')
    _commit(unit, "cycle")
    tip = tf_validate._tip_files(str(repo), tf_validate.unit_tip(str(repo), BRANCH))
    assert tip is not None
    root = tf_validate.Root("infra")
    tf_validate._read_folder(tip, root, "infra", "", 0, {})
    assert "nest deeper or wider" in root.reason
    assert mirror.exists()


@pytest.mark.parametrize("name", ["a b", "-rf", "$(touch pwned);`id`", "-chdir=x", "x\\y"])
def test_a_folder_or_file_name_cannot_change_any_command(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / name).mkdir()
    (unit / name / f"{name}.tf").write_text(NULL, encoding="utf-8")
    (unit / name / "-get=true.tf").write_text("# x\n", encoding="utf-8")
    _commit(unit, "names")
    bin_dir = tmp_path / "bin"
    tool = _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert (code, out) == (0, [f"validate: {name}: validated clean."])
    init, check = _calls(bin_dir)
    assert init["argv"] == [str(tool.resolve()), *tf_validate.INIT_ARGS]
    assert check["argv"] == [str(tool.resolve()), *tf_validate.VALIDATE_ARGS]
    assert set(_files(init)) == {f"{name}/{name}.tf", f"{name}/-get=true.tf"}
    assert not list(tmp_path.rglob("pwned"))


def test_a_link_a_huge_file_and_a_non_regular_entry_leave_the_root_not_validated(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    secret = tmp_path / "secret.tf"
    secret.write_text('# secret\nlocals { k = "SECRET-VALUE" }\n', encoding="utf-8")
    (unit / "linked").mkdir()
    (unit / "linked" / "main.tf").symlink_to(secret)
    (unit / "huge").mkdir()
    (unit / "huge" / "main.tf").write_text("#" * (provider_mirror.MAX_TF_BYTES + 1))
    (unit / "sub").mkdir()
    (unit / "sub" / "real.tf").write_text("# x\n", encoding="utf-8")
    git(unit, "add", "-A")
    head = git(unit, "rev-parse", "HEAD").stdout.strip()
    git(unit, "update-index", "--add", "--cacheinfo", f"160000,{head},sub/gitlink.tf")
    git(unit, "commit", "-qm", "odd entries")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0 and _calls(bin_dir) == []
    assert out == [
        "validate: huge: not validated, because huge/main.tf is larger than "
        f"{provider_mirror.MAX_TF_BYTES} bytes. {tf_validate.NEXT_UNSTAGED}",
        "validate: linked: not validated, because linked/main.tf is a link or not a regular "
        f"file. {tf_validate.NEXT_UNSTAGED}",
        "validate: sub: not validated, because sub/gitlink.tf is a link or not a regular file. "
        f"{tf_validate.NEXT_UNSTAGED}",
    ]
    assert "SECRET" not in json.dumps(train_state.load(repo, TRAIN))


def test_the_environment_holds_no_caller_config_args_cache_token_or_path(
    tmp_path: Path, tmp_root: Path
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + "# env\n", encoding="utf-8")
    _commit(unit, "env")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    source = {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path / "home"),
        "TF_CLI_CONFIG_FILE": str(repo / "infra" / ".terraformrc"),
        "TF_CLI_ARGS": "-chdir=/etc",
        "TF_CLI_ARGS_init": "-get=true",
        "TF_CLI_ARGS_validate": "-no-tests=false",
        "TF_PLUGIN_CACHE_DIR": str(repo / "cache"),
        "TF_REATTACH_PROVIDERS": '{"x": {}}',
        "TF_TOKEN_app_terraform_io": "tok-SECRET-1234",
        "HTTPS_PROXY": "http://user:pw-SECRET@proxy:3128",
        "TF_LOG_PATH": str(repo / "log.txt"),
        "TF_DATA_DIR": str(unit / "infra" / ".terraform"),
    }
    unit_record = tf_validate.Unit(UNIT, f"{TRAIN}-{UNIT}", BRANCH)
    lines, _ = tf_validate.validate(str(repo), TRAIN, unit_record, (), source)
    assert lines == ["validate: infra: validated clean."]
    for call in _calls(bin_dir):
        env = call["env"]
        assert isinstance(env, dict)
        stage = str(call["stage"])
        # PEP 538: the stand-in's own interpreter adds LC_CTYPE when it coerces the C locale.
        assert set(env) - {"LC_CTYPE"} == set(provider_mirror.FIXED_ENV) | {
            "HOME",
            "PATH",
            "TF_CLI_CONFIG_FILE",
            "TF_DATA_DIR",
        }
        assert env["PATH"] == ""
        assert env["HOME"] == f"{stage}/home" and env["TF_DATA_DIR"] == f"{stage}/data"
        assert env["TF_CLI_CONFIG_FILE"] == f"{stage}/terraformrc"
        assert not any(k.startswith(("TF_CLI_ARGS", "TF_TOKEN_")) for k in env)
    assert not (repo / "log.txt").exists() and not (repo / "cache").exists()


def test_failed_diagnostics_route_back_and_print_only_safe_summaries(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + 'resource "null_resource" "a" {}\n')
    _commit(unit, "broken")
    stage_hint = str(storage.tmp_dir(tf_validate.FEATURE, repo))

    def diag(summary: str, filename: str, detail: str = "TOPSECRET detail") -> dict[str, object]:
        where = {"filename": filename, "start": {"line": 3, "column": 1}}
        return {"severity": "error", "summary": summary, "detail": detail, "range": where}

    payload = {
        "valid": False,
        "diagnostics": [
            diag("Unsupported argument", "main.tf"),
            diag("Bad \x1b[31mred\x1b[0m\r\nline", "../modules/x/main.tf"),
            diag("Read /etc/passwd failed", "/etc/passwd"),
            diag("Cannot read " + stage_hint + "/x", "/root/.ssh/id_rsa"),
            {"severity": "warning", "summary": "warned TOPSECRET", "detail": "x"},
            diag("x" * 500, "main.tf"),
            diag("sixth", "main.tf"),
        ],
    }
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "fail", json.dumps(payload))
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 2
    assert out[0] == "validate: infra: failed; terraform validate reported:"
    assert out[1] == "validate:   infra/main.tf:3: Unsupported argument"
    assert out[2] == "validate:   modules/x/main.tf:3: Bad [31mred[0mline"
    assert out[3] == "validate:   [withheld]:3: Read [withheld] failed"
    assert out[4] == "validate:   [withheld]:3: Cannot read [withheld]"
    assert out[5] == f"validate:   infra/main.tf:3: {'x' * tf_validate.SUMMARY_MAX}"
    assert out[6] == "validate:   and 1 more."
    assert out[-1] == tf_validate.NEXT_ROUTE
    text = "\n".join(out) + json.dumps(train_state.load(repo, TRAIN))
    assert "TOPSECRET" not in text and "\x1b" not in text and "/etc/passwd" not in text
    assert all(line.isprintable() for line in out)
    assert _record(repo)["roots"][0]["result"] == "failed"  # type: ignore[index]


def test_a_hang_is_killed_with_its_process_group(tmp_path: Path, tmp_root: Path) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + "# hang\n", encoding="utf-8")
    _commit(unit, "hang")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "hang")
    unit_record = tf_validate.Unit(UNIT, f"{TRAIN}-{UNIT}", BRANCH)
    started = time.monotonic()
    lines, outcomes = tf_validate.validate(
        str(repo), TRAIN, unit_record, (), {"PATH": str(bin_dir)}, timeout=1
    )
    assert time.monotonic() - started < 15
    assert [o.result for o in outcomes] == [tf_validate.NOT_VALIDATED]
    assert "did not finish within 1 seconds" in lines[0]
    child = int((bin_dir / "child").read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{child}/stat").read_text().split(") ")[1][0]
        except (FileNotFoundError, IndexError):
            break
        if state == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("the hung child kept running")


def test_a_provider_the_mirror_lacks_asks_the_operator_before_any_run(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "aws.tf").write_text(
        'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n'
        '      version = "~> 5.0"\n    }\n  }\n}\nresource "random_id" "r" {}\n',
        encoding="utf-8",
    )
    _commit(unit, "aws")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 3 and _calls(bin_dir) == []
    assert out == [
        "validate: infra: not validated, because it needs the provider "
        "registry.terraform.io/hashicorp/aws (version ~> 5.0), "
        "registry.terraform.io/hashicorp/random (version none stated), which the run's mirror "
        f"lacks. {tf_validate.NEXT_PROVIDER}"
    ]


def test_a_version_the_mirror_lacks_asks_the_operator_too(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL.replace("3.2.3", "9.9.9"), encoding="utf-8")
    _commit(unit, "version")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "missing")
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 3
    assert out == [
        "validate: infra: not validated, because it needs a provider version the run's mirror "
        "lacks; the files name registry.terraform.io/hashicorp/null (version 9.9.9). "
        f"{tf_validate.NEXT_PROVIDER}"
    ]


def test_an_unreadable_init_result_is_not_routed(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + "# junk\n", encoding="utf-8")
    _commit(unit, "junk")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir, "junk")
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0
    assert out[0].startswith("validate: infra: not validated, because terraform init gave no")


def test_nothing_to_validate_and_no_mirror_both_go_on(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    (unit / "README.md").write_text("x\n", encoding="utf-8")
    _commit(unit, "docs")
    bin_dir = tmp_path / "bin"
    _stand_in(bin_dir)
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert (code, out) == (
        0,
        ["validate: the unit changes no Terraform file, so nothing was validated."],
    )
    (unit / "infra" / "main.tf").write_text(NULL + "# x\n", encoding="utf-8")
    _commit(unit, "tf")
    code, out = _run(repo, monkeypatch, bin_dir, capsys)
    assert code == 0 and out == [
        f"warning: validate: nothing was validated, because {tf_validate.NO_MIRROR}"
    ]
    assert _calls(bin_dir) == []


def test_a_terraform_inside_the_project_is_never_run(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, unit = _project(tmp_path)
    _mirror(repo)
    (unit / "infra" / "main.tf").write_text(NULL + "# x\n", encoding="utf-8")
    _commit(unit, "tf")
    planted = repo / "tools"
    _stand_in(planted)
    code, out = _run(repo, monkeypatch, planted, capsys)
    assert code == 0 and "no terraform outside the project is on PATH" in out[0]
    assert _calls(planted) == []


def test_only_the_orchestrator_may_run_the_command() -> None:
    # 0265: the orchestrator's train class admits validate by name; no other agent runs it.
    assert decide(_b("orchestrator", VALIDATE), CFG).allow
    for agent in ("coder", "auditor", "verifier", "releaser", "charter-docs", "writer"):
        assert not decide(_b(agent, VALIDATE), CFG).allow, agent


@pytest.mark.parametrize(
    ("value", "want"),
    [
        (
            '{ source = "hashicorp/null", version = "3.2.3" }',
            {"source": "hashicorp/null", "version": "3.2.3"},
        ),
        ('{\n  source = "a/b"\n  version = "~> 1.0"\n}', {"source": "a/b", "version": "~> 1.0"}),
        ('{ "source" : "a/b", configuration_aliases = [aws.x, aws.y] }', {"source": "a/b"}),
        ("var.x", None),
    ],
)
def test_the_required_providers_object_is_read_by_tokens(
    value: str, want: dict[str, str] | None
) -> None:
    assert tf_validate._object_strings(value) == want
