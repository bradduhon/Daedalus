# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0192: the asset exclusion tail, its size listing and the train subcommand that prints it.
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lib import assets
from lib.manifest import Assets

from tests.conftest import CFG, CWD, SCRIPTS_DIR, run_cli
from tests.hook_chain import first_deny
from tests.payloads import _b

GAME = Assets(("assets/", "public/models/"), (".glb", ".wav"), 1000)


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return done.stdout


def _repo(tmp_path: Path, manifest: dict[str, object] | None = None) -> tuple[Path, str]:
    repo = tmp_path / "game"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "keep.txt").write_text("x\n", encoding="utf-8")
    # A deleted text file, unlike any added file, so git reports no rename.
    (repo / "gone.bin").write_text("a deleted line of plain text\n" * 200, encoding="utf-8")
    if manifest is not None:
        (repo / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
    for rel, size in (
        ("assets/hero.glb", 9000),
        ("public/models/tree.bin", 9000),
        ("web/sound.wav", 9000),
        ("web/big.bin", 2000),
        ("web/small.ts", 10),
        ("web/odd name.bin", 3000),
    ):
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"a" * size)
    (repo / "gone.bin").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "assets")
    return repo, base


def test_the_tails_render_each_root_and_ending_once() -> None:
    assert assets.diff_tail(GAME) == (
        "-- . ':(exclude)assets/' ':(exclude)public/models/' ':(exclude)*.glb' ':(exclude)*.wav'"
    )
    assert assets.log_opts_tail(GAME, ("web/big.bin",)) == (
        "-- . :(exclude)assets/ :(exclude)public/models/ :(exclude)*.glb :(exclude)*.wav "
        ":(exclude)web/big.bin"
    )
    assert assets.diff_tail(Assets()) == "" and assets.log_opts_tail(Assets()) == ""
    assert assets.lines(Assets(), []) == ["Assets: none"]


def test_matches_takes_a_root_prefix_or_an_ending() -> None:
    assert assets.matches(GAME, "assets/hero.glb") and assets.matches(GAME, "assets")
    assert assets.matches(GAME, "web/x.wav") and assets.matches(GAME, "public/models/a/b.png")
    assert not assets.matches(GAME, "assetsx/a.png") and not assets.matches(GAME, "web/x.WAV")


def test_oversized_lists_changed_files_by_name_and_skips_assets_and_deletions(
    tmp_path: Path,
) -> None:
    repo, base = _repo(tmp_path)
    found = assets.oversized(repo, base, "HEAD", GAME)
    assert found == [
        assets.Oversized("web/big.bin", 2000, True),
        assets.Oversized("web/odd name.bin", 3000, False),
    ]
    assert assets.oversized(repo, base, "HEAD", Assets(("assets/",))) == []
    lines = assets.lines(GAME, found)
    assert lines[0].endswith("':(exclude)*.wav' ':(exclude)web/big.bin'")
    assert lines[1].startswith("Assets log-opts: -- . :(exclude)assets/")
    assert lines[2:] == [
        "Over size: web/big.bin (2000 bytes)",
        "Over size: web/odd name.bin (3000 bytes, kept in the diff: no exclusion can carry its "
        "name)",
    ]


@pytest.mark.parametrize(("base", "tip"), [("-x", "HEAD"), ("abc", ""), ("nope", "HEAD")])
def test_oversized_refuses_a_bad_range(tmp_path: Path, base: str, tip: str) -> None:
    repo, _ = _repo(tmp_path)
    with pytest.raises(assets.AssetsError, match="Next: "):
        assets.oversized(repo, base, tip, GAME)


def test_the_tail_drops_only_asset_files_from_git_diff_and_git_log(tmp_path: Path) -> None:
    # 0192, 0128: every source file stays in the diff; only asset files leave it.
    repo, base = _repo(tmp_path)
    extra = ("web/big.bin",)
    words = assets.log_opts_tail(GAME, extra).split()
    names = _git(repo, "diff", "--name-only", f"{base}...HEAD", *words).split("\n")
    assert sorted(n for n in names if n) == ["gone.bin", "web/odd name.bin", "web/small.ts"]
    assert _git(repo, "log", "--oneline", f"{base}..HEAD", *words).count("\n") == 1
    only_assets = ("assets/", "public/models/", "web/")
    words = assets.log_opts_tail(Assets(only_assets), ()).split()
    assert _git(repo, "log", "--oneline", f"{base}..HEAD", *words).strip().endswith("assets")


def test_the_assets_subcommand_prints_the_tails_and_the_large_files(tmp_path: Path) -> None:
    block = {"roots": ["assets/", "public/models/"], "extensions": [".glb", ".wav"]}
    repo, base = _repo(tmp_path, {"assets": {**block, "max_bytes": 1000}})
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
    lines = done.stdout.splitlines()
    assert lines[0] == f"Assets: {assets.diff_tail(GAME, ('web/big.bin',))}"
    assert lines[1] == f"Assets log-opts: {assets.log_opts_tail(GAME, ('web/big.bin',))}"
    assert lines[2] == "Over size: web/big.bin (2000 bytes)"


def test_the_assets_subcommand_prints_none_without_a_block(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"manifest_version": 1})
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


def test_the_assets_subcommand_stops_on_a_bad_manifest_or_range(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"assets": {"roots": ["../x/"], "max_bytes": 5}})
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
    assert "assets.roots" in done.stdout and "Next:" in done.stdout


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
    (tmp_path / "assets" / "loader.ts").write_text("", encoding="utf-8")
    manifest = {"assets": {"roots": ["assets/"], "extensions": [".glb"], "max_bytes": 1048576}}
    (tmp_path / "service-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    lines = [line for _, line in daedalus_doctor._assets_check(tmp_path)]
    assert lines[0] == (
        "OK   assets: 1 root, 1 ending, changed files over 1048576 bytes listed by name, kept "
        "out of the judges' diffs and the secret scan"
    )
    assert lines[1:] == [
        f"OPT  asset root source file {rel}: a source file under an asset root is never read "
        "by the judges or scanned for secrets. Next: move it out of the asset root, or narrow "
        "assets.roots in service-manifest.json"
        for rel in ("assets/levels/one.json", "assets/loader.ts")
    ]
    assert all(ok for ok, _ in daedalus_doctor._assets_check(tmp_path))
    (tmp_path / "service-manifest.json").write_text("{}", encoding="utf-8")
    assert list(daedalus_doctor._assets_check(tmp_path)) == []
