# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 52: the readers of features.secrets_scan and trains_dir.
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from lib import train_runner

from tests import test_train_runner as runner_tests
from tests.conftest import REPO_ROOT, SCRIPTS_DIR, fake_bin
from tests.test_train_runner import (
    _code_stage,
    _definition,
    _prompt,
    _started,
    _state,
    _step,
    _write_train,
)

# The runner tests' fixtures: a temp HOME, a plugin root and a one-commit repository.
_isolated_env = runner_tests._isolated_env
plugin = runner_tests.plugin
repo = runner_tests.repo
PROJECT_TEMPLATE = "Project brief for train {train_id}.\n"


def _project_train(root: Path, folder: str = "ops/trains") -> Path:
    # 0073: a project definition whose brief template sits beside it, under trains_dir.
    (root / "service-manifest.json").write_text(json.dumps({"trains_dir": folder}))
    defn = root / folder / "t.json"
    template = defn.parent / "trains" / "t" / "solo.md"
    template.parent.mkdir(parents=True)
    template.write_text(PROJECT_TEMPLATE)
    defn.write_text(json.dumps(_definition([_code_stage()], ("repository",))))
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "trains"], check=True)
    return defn


def test_trains_dir_definition_wins_over_the_plugin(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    defn = _project_train(repo)
    _started(repo, plugin)
    assert _state(repo)["definition"] == str(defn.resolve())


def test_project_brief_resolves_beside_its_definition(repo: Path, plugin: Path) -> None:
    _project_train(repo)
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    train = _state(repo)["train_id"]
    assert brief.read_text().startswith(f"Project brief for train {train}.")


def test_trains_dir_without_the_name_falls_back_to_the_plugin(repo: Path, plugin: Path) -> None:
    path = _write_train(plugin, [_code_stage()], ("repository",))
    (repo / "service-manifest.json").write_text(json.dumps({"trains_dir": "ops/trains"}))
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "manifest"], check=True)
    _started(repo, plugin)
    assert _state(repo)["definition"] == str(path.resolve())


def test_trains_dir_definition_leaving_the_project_is_refused(
    repo: Path, plugin: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_definition([_code_stage()], ("repository",))))
    (repo / "service-manifest.json").write_text(json.dumps({"trains_dir": "ops"}))
    (repo / "ops").mkdir()
    (repo / "ops" / "t.json").symlink_to(outside)
    outcome = train_runner.start(repo, "t", None, plugin)
    assert outcome.code == 1
    assert "resolves outside the project" in outcome.lines[0]
    assert not (repo / ".claude" / "daedalus" / "train.active").exists()


def test_a_malformed_manifest_stops_start_before_the_lookup(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    (repo / "service-manifest.json").write_text(json.dumps({"trains_dir": "/abs"}))
    outcome = train_runner.start(repo, "t", None, plugin)
    assert outcome.code == 1 and "trains_dir" in outcome.lines[0]


def _doctor(root: Path, tmp_path: Path, *args: str, bins: tuple[str, ...] = ()) -> list[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_PLUGIN_DATA", None)
    env["PATH"] = str(fake_bin(tmp_path, bins, None))
    env["HOME"] = str(tmp_path / "home")
    argv = [sys.executable, str(SCRIPTS_DIR / "daedalus_doctor.py"), "--repo", str(root), *args]
    done = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    return [str(done.returncode), *done.stdout.splitlines(), *done.stderr.splitlines()]


def _features(root: Path, features: object) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "service-manifest.json").write_text(json.dumps({"features": features}))


def test_print_secrets_scan_reads_the_feature(tmp_path: Path) -> None:
    on, off, bare = tmp_path / "on", tmp_path / "off", tmp_path / "bare"
    _features(on, {"secrets_scan": True})
    _features(off, {"secrets_scan": False})
    bare.mkdir()
    assert _doctor(on, tmp_path, "--print-secrets-scan") == ["0", "secrets scan: on"]
    assert _doctor(off, tmp_path, "--print-secrets-scan") == ["0", "secrets scan: off"]
    assert _doctor(bare, tmp_path, "--print-secrets-scan") == ["0", "secrets scan: off"]


def test_print_secrets_scan_refuses_a_malformed_manifest(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    _features(bad, {"secrets_scan": "yes"})
    out = _doctor(bad, tmp_path, "--print-secrets-scan")
    assert out[0] == "1" and "features.secrets_scan" in out[1] and "Next:" in out[1]


def _gitleaks_line(lines: list[str]) -> str:
    return next(line for line in lines if "gitleaks on PATH" in line)


def test_doctor_gitleaks_line_follows_the_feature(tmp_path: Path) -> None:
    on, off, bad = tmp_path / "on", tmp_path / "off", tmp_path / "bad"
    _features(on, {"secrets_scan": True})
    _features(off, {})
    _features(bad, {"secrets_scan": 1})
    assert _gitleaks_line(_doctor(on, tmp_path)).startswith("MISS gitleaks on PATH: not found.")
    assert _gitleaks_line(_doctor(off, tmp_path)).startswith("OPT  gitleaks on PATH: not found")
    # 0069: a refused manifest counts as scan on, so the missing tool is still a MISS.
    assert _gitleaks_line(_doctor(bad, tmp_path)).startswith("MISS gitleaks on PATH")
    found = _doctor(off, tmp_path, bins=("gitleaks",))
    assert _gitleaks_line(found) == "OK   gitleaks on PATH"


def test_push_train_runs_gitleaks_only_with_the_scan_on() -> None:
    text = (REPO_ROOT / "skills" / "push-train" / "SKILL.md").read_text(encoding="utf-8")
    step = text.split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert step.startswith(
        "Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --print-secrets-scan"
    )
    assert step.index("With the scan on, run `gitleaks version`") < step.index("gh auth status")
    assert "With the scan off, gitleaks is not run" in step
    push = text.split("\n## Push\n", 1)[1].split("\n## ", 1)[0]
    scan = next(line for line in push.splitlines() if "gitleaks detect" in line)
    assert scan.endswith("Include this line only when step 5 recorded the scan on.")
