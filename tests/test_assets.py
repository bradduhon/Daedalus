# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0192: the asset exclusion tail, its size listing and the train subcommand that prints it.
# 0128: a file with a source ending is never excluded, by root, by ending or by size.
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from lib import assets
from lib.manifest import SOURCE_EXTENSIONS, Assets, is_source

from tests.conftest import CFG, CWD, SCRIPTS_DIR, run_cli
from tests.hook_chain import first_deny
from tests.payloads import _b

GAME = Assets(("assets/", "public/models/"), (".glb", ".wav"), 1000)
# Built at run time so this file never holds a token-shaped literal for the repo's own scan.
FAKE_TOKEN = "ghp_" + "R3xQm7Lp2Vn8Kd4Ws9Tj6Hb1Yc5Fg0Ze7Ua2"


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return done.stdout


def _init(tmp_path: Path, manifest: dict[str, object] | None = None) -> tuple[Path, str]:
    repo = tmp_path / "game"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "keep.txt").write_text("x\n", encoding="utf-8")
    if manifest is not None:
        (repo / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo, _git(repo, "rev-parse", "HEAD").strip()


def _commit(repo: Path, files: dict[str, bytes], message: str = "change") -> None:
    for rel, body in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _changed(repo: Path, base: str, found: assets.Exclusion) -> list[str]:
    words = assets.log_opts_tail(found).split()
    return sorted(
        n for n in _git(repo, "diff", "--name-only", f"{base}...HEAD", *words).split("\n") if n
    )


def test_the_source_endings_are_one_tuple_and_casefolded() -> None:
    for ending in (".sh", ".mjs", ".env", ".tfvars", ".pyi", ".sql", ".html", ".txt"):
        assert ending in SOURCE_EXTENSIONS, ending
    assert len(SOURCE_EXTENSIONS) == len(set(SOURCE_EXTENSIONS))
    assert is_source("web/App.TSX") and is_source(".env") and not is_source("hero.glb")
    assert assets.excluded(GAME, "assets/hero.png")
    assert not assets.excluded(GAME, "assets/loader.ts") and not assets.excluded(GAME, "a.py")


def test_the_tails_render_each_root_ending_and_name_once() -> None:
    found = assets.Exclusion(("assets/",), (".glb",), ("public/models/tree.bin",))
    assert assets.diff_tail(found) == (
        "-- . ':(exclude)assets/' ':(exclude)*.glb' ':(exclude)public/models/tree.bin'"
    )
    assert assets.log_opts_tail(found) == (
        "-- . :(exclude)assets/ :(exclude)*.glb :(exclude)public/models/tree.bin"
    )
    assert assets.lines(assets.Exclusion()) == ["Assets: none"]


def test_h1_an_oversized_source_file_with_a_token_stays_in_the_diff_and_the_scan(
    tmp_path: Path,
) -> None:
    # H1 probe: max_bytes 200, a 319-byte src/big.py holding a token is never excluded.
    repo, base = _init(tmp_path)
    body = f'TOKEN = "{FAKE_TOKEN}"\n'.encode()
    body += b"#" * (318 - len(body)) + b"\n"
    assert len(body) == 319
    _commit(repo, {"src/big.py": body, "assets/hero.glb": b"g" * 50})
    declared = Assets(("assets/",), (".glb",), 200)
    found = assets.exclusion(repo, base, "HEAD", declared)
    assert "src/big.py" not in assets.diff_tail(found)
    assert "src/big.py" not in assets.log_opts_tail(found)
    assert found.over == () and "Over size" not in "\n".join(assets.lines(found))
    assert _changed(repo, base, found) == ["src/big.py"]
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks is not installed; the diff half of the probe passed")
    opts = f"--log-opts={base}..HEAD {assets.log_opts_tail(found)}"
    scan = subprocess.run(
        ["gitleaks", "detect", "--redact", "--no-banner", opts],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert scan.returncode == 1 and "leaks found: 1" in scan.stderr, scan.stderr


def test_a_source_file_under_an_asset_root_keeps_that_root_in_the_diff(tmp_path: Path) -> None:
    # 0192: the root is no longer dropped whole; its asset files are dropped one by one.
    repo, base = _init(tmp_path)
    _commit(
        repo,
        {
            "assets/loader.ts": b"export const x = 1\n",
            "assets/tree.bin": b"t" * 10,
            "assets/hero.glb": b"g" * 10,
            "assets/odd name.bin": b"o" * 10,
            "public/models/rock.bin": b"r" * 10,
        },
    )
    found = assets.exclusion(repo, base, "HEAD", GAME)
    assert found.roots == ("public/models/",)
    assert found.names == ("assets/tree.bin",)
    assert found.root_sources == ("assets/loader.ts",)
    assert found.kept == ("assets/odd name.bin",)
    assert _changed(repo, base, found) == ["assets/loader.ts", "assets/odd name.bin"]
    lines = assets.lines(found)
    assert "Asset root source: assets/loader.ts" in lines
    assert "Kept in the diff: assets/odd name.bin (no exclusion can carry its name)" in lines


def test_a_source_file_touched_then_deleted_in_the_range_still_keeps_its_root(
    tmp_path: Path,
) -> None:
    # 0192: the secret scan reads every commit, so a path any commit touches counts.
    repo, base = _init(tmp_path)
    _commit(repo, {"assets/leak.env": b"KEY=x\n", "assets/a.bin": b"a"}, "add")
    (repo / "assets" / "leak.env").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove")
    found = assets.exclusion(repo, base, "HEAD", Assets(("assets/",)))
    assert found.roots == () and found.root_sources == ("assets/leak.env",)
    assert found.names == ("assets/a.bin",)


def test_an_asset_over_the_cap_is_listed_and_excluded(tmp_path: Path) -> None:
    repo, base = _init(tmp_path)
    _commit(
        repo,
        {
            "web/hero.glb": b"g" * 2000,
            "assets/small.png": b"p" * 10,
            "web/big.bin": b"b" * 5000,
        },
    )
    found = assets.exclusion(repo, base, "HEAD", GAME)
    assert found.over == (("web/hero.glb", 2000),)
    assert _changed(repo, base, found) == ["web/big.bin"]
    assert assets.lines(found)[2:] == ["Over size: web/hero.glb (2000 bytes)"]
    assert "hero.glb" not in assets.log_opts_tail(found)


@pytest.mark.parametrize(("base", "tip"), [("-x", "HEAD"), ("abc", ""), ("nope", "HEAD")])
def test_exclusion_refuses_a_bad_range(tmp_path: Path, base: str, tip: str) -> None:
    repo, _ = _init(tmp_path)
    with pytest.raises(assets.AssetsError, match="Next: "):
        assets.exclusion(repo, base, tip, GAME)


def test_no_assets_block_runs_no_git(tmp_path: Path) -> None:
    assert assets.exclusion(tmp_path, "-x", "", Assets()) == assets.Exclusion()


def test_the_assets_subcommand_prints_the_tails_and_the_large_files(tmp_path: Path) -> None:
    block = {"roots": ["assets/"], "extensions": [".glb"], "max_bytes": 100}
    repo, base = _init(tmp_path, {"assets": block})
    _commit(repo, {"web/hero.glb": b"g" * 500, "src/main.py": b"print(1)\n"})
    done = run_cli(
        "daedalus_train.py",
        "assets",
        "--repo",
        str(repo),
        "--base",
        base,
        "--tip",
        "HEAD",
        cwd=repo,
    )
    assert done.returncode == 0, done.stdout
    assert done.stdout.splitlines() == [
        "Assets: -- . ':(exclude)assets/' ':(exclude)*.glb'",
        "Assets log-opts: -- . :(exclude)assets/ :(exclude)*.glb",
        "Over size: web/hero.glb (500 bytes)",
    ]


def test_the_assets_subcommand_prints_none_without_a_block(tmp_path: Path) -> None:
    repo, base = _init(tmp_path, {"manifest_version": 1})
    done = run_cli(
        "daedalus_train.py",
        "assets",
        "--repo",
        str(repo),
        "--base",
        base,
        "--tip",
        "HEAD",
        cwd=repo,
    )
    assert (done.returncode, done.stdout) == (0, "Assets: none\n")


def test_the_assets_subcommand_stops_on_a_bad_manifest(tmp_path: Path) -> None:
    repo, base = _init(tmp_path, {"assets": {"extensions": [".py"]}})
    done = run_cli(
        "daedalus_train.py",
        "assets",
        "--repo",
        str(repo),
        "--base",
        base,
        "--tip",
        "HEAD",
        cwd=repo,
    )
    assert done.returncode == 1 and done.stdout.startswith("assets: ")
    assert "assets.extensions" in done.stdout and "Next:" in done.stdout


def test_the_orchestrator_may_run_the_assets_subcommand() -> None:
    # 0192: the train class admits assets beside packs and brief-check; no worker runs it.
    command = (
        f"python3 {SCRIPTS_DIR}/daedalus_train.py assets --repo {CWD} --base abc123 "
        "--tip daedalus/t"
    )
    assert first_deny(_b("orchestrator", command), CFG) is None
    for agent in ("coder", "auditor", "verifier", "releaser"):
        assert first_deny(_b(agent, command), CFG) is not None, agent


def test_the_doctor_warns_once_per_source_file_under_an_asset_root(tmp_path: Path) -> None:
    import daedalus_doctor

    (tmp_path / "assets" / "levels").mkdir(parents=True)
    (tmp_path / "assets" / "hero.glb").write_bytes(b"x")
    (tmp_path / "assets" / "levels" / "one.json").write_text("{}", encoding="utf-8")
    (tmp_path / "assets" / "run.sh").write_text("", encoding="utf-8")
    manifest = {"assets": {"roots": ["assets/"], "extensions": [".glb"], "max_bytes": 1048576}}
    (tmp_path / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    lines = [line for _, line in daedalus_doctor._assets_check(tmp_path)]
    assert lines[0] == (
        "OK   assets: 1 root, 1 ending, asset files over 1048576 bytes listed by name, kept out "
        "of the judges' diffs and the secret scan; source files never are"
    )
    assert lines[1:] == [
        f"OPT  asset root source file {rel}: a source file under an asset root keeps that root "
        "in every diff, and the auditor treats a change to it as a finding. Next: move it out "
        "of the asset root, or narrow assets.roots in service-manifest.json"
        for rel in ("assets/levels/one.json", "assets/run.sh")
    ]
    assert all(ok for ok, _ in daedalus_doctor._assets_check(tmp_path))
    (tmp_path / "service-manifest.json").write_text("{}", encoding="utf-8")
    assert list(daedalus_doctor._assets_check(tmp_path)) == []
