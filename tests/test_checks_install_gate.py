# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0196: the network_tools install class over the rows in tests/fixtures/installs.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from checks import confine
from lib import jail, shell
from lib.manifest import INSTALL_ECOSYSTEMS, ManifestError
from lib.manifest import load as load_manifest

from tests.conftest import REPO_ROOT
from tests.hook_chain import evaluate
from tests.payloads import _b, _cwd

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "network_tools"
ROWS: list[dict[str, str]] = json.loads(
    (REPO_ROOT / "tests" / "fixtures" / "installs" / "commands.json").read_text(encoding="utf-8")
)
JUDGES = ("auditor", "verifier")
# 228 S3b: no-install rows off the coder's command table or runner rows; the S3b return names them.
CODER_OFF_TABLE = frozenset(
    {"terraform init", "terraform init -upgrade=false", "pnpm -- dev", "npm init -y"}
    | {"npm exec --no-install vitest run", "npm exec --no-install -- eslint ."}
    | {"node_modules/.bin/eslint .", ".venv/bin/ruff check ."}
    | {"deno run main.ts", "deno run --config cfg.json main.ts"}
)
GAP = pytest.mark.xfail(strict=True, reason="228 S3b table gap: no frozen install row")


def _repo(tmp_path: Path, installs: list[str] | None) -> Path:
    # 0196: a project root whose manifest lists installs, or carries no dependencies block.
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    doc: dict[str, Any] = {"manifest_version": 1}
    if installs is not None:
        doc["dependencies"] = {"installs": installs}
    (repo / "service-manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    return repo


def _judge(agent: str, command: str, repo: Path) -> str | None:
    return evaluate(HOOK, _cwd(_b(agent, command), repo))


def test_the_fixture_covers_every_manager_and_kind() -> None:
    commands = [row["command"] for row in ROWS]
    assert len(commands) >= 40 and len(set(commands)) == len(commands)
    words = {shell._base(c.split()[0]) for c in commands} | {w for c in commands for w in c.split()}
    managers = {"pip", "pip3", "python3", "uv", "poetry", "npm", "pnpm", "yarn", "bun", "cargo"}
    assert managers | {"go", "gem", "bundle", "composer", "terraform", "pdm", "pipx"} <= words
    kinds = {"frozen", "refused", "operator", "launcher", "none"}
    assert {row["kind"] for row in ROWS} == kinds
    # 0196 addendum: each launcher in its refused and its installed-binary shape.
    launchers = {"npx", "exec", "dlx", "bunx", "x", "uvx", "tool", "pipx", "deno"}
    seen = {w for row in ROWS if row["kind"] == "launcher" for w in row["command"].split()}
    assert launchers <= seen
    allowed = ("npx --no-install", "npm exec --no-install", "pnpm exec", "yarn run", "bun run")
    for form in (*allowed, "node_modules/.bin/", ".venv/bin/", "python3 -m", "deno run main"):
        none = [row["command"] for row in ROWS if row["kind"] == "none"]
        assert any(command.startswith(form) for command in none), form
    assert {row["ecosystem"] for row in ROWS if row["kind"] == "frozen"} == set(INSTALL_ECOSYSTEMS)


@pytest.mark.parametrize("row", ROWS, ids=[row["command"] for row in ROWS])
def test_the_install_class_judges_each_fixture_row(row: dict[str, str], tmp_path: Path) -> None:
    # 0196: refused for every agent; a coder's frozen form passes only with its ecosystem listed.
    command, kind = row["command"], row["kind"]
    every = _repo(tmp_path / "every", list(INSTALL_ECOSYSTEMS))
    other = [e for e in INSTALL_ECOSYSTEMS if e != row.get("ecosystem")]
    for repo in (every, _repo(tmp_path / "none", None), _repo(tmp_path / "other", other)):
        # 228 S3b: the coder's grammar admits no install and names the word it refused.
        got = _judge("coder", command, repo)
        if kind == "none" and command not in CODER_OFF_TABLE:
            assert got is None, (repo.parent.name, command, got)
        else:
            assert got is not None and "Refused: " in got, (repo.parent.name, command, got)
        for agent in JUDGES:
            got = _judge(agent, command, repo)
            if kind == "none":
                assert got is None, (agent, repo.parent.name, command, got)
                continue
            assert got is not None and "(0196" in got, (agent, command, got)
            if kind == "launcher":
                assert "downloads a package and runs it" in got, (command, got)
                assert "Next: run the installed binary instead (" in got, (command, got)
            elif kind == "operator":
                assert got.startswith(shell._base(command.split()[0])), (command, got)
                assert "no frozen, scripts-off form" in got, (command, got)
            else:
                assert "Next: run the frozen form (" in got, (command, got)
                assert "with the ecosystem enabled in service-manifest.json" in got


@pytest.mark.parametrize(
    "row", [r for r in ROWS if r["kind"] == "frozen"], ids=lambda r: r["command"]
)
def test_a_frozen_form_chained_with_another_install_refuses(
    row: dict[str, str], tmp_path: Path
) -> None:
    # 0196: every segment is judged, and a frozen form behind a prefix word is never the exception.
    repo = _repo(tmp_path, list(INSTALL_ECOSYSTEMS))
    command = row["command"]
    for chained in (f"{command} && npm install left-pad", f"pip install x; {command}"):
        assert _judge("coder", chained, repo) is not None, chained
    for prefixed in (f"FOO=1 {command}", f"pnpm exec {command}"):
        assert _judge("coder", prefixed, repo) is not None, prefixed


@GAP
@pytest.mark.parametrize("command", ["npm ci --ignore-scripts", "cargo fetch --locked"])
def test_a_coders_frozen_form_runs_with_its_ecosystem_listed(command: str, tmp_path: Path) -> None:
    # 0196, 228 S3b: the frozen form is on no coder table row yet; a row with a test fixes it.
    repo = _repo(tmp_path, list(INSTALL_ECOSYSTEMS))
    assert _judge("coder", command, repo) is None
    assert _judge("coder", f"cd {repo} && {command}", repo) is None


def test_the_refusal_names_what_and_the_frozen_form() -> None:
    reason = jail.install_reason(["pip", "install", "requests"], frozenset)
    assert reason is not None and reason.startswith("pip install is a package install")
    assert jail.FROZEN_EXAMPLES["pip"] in reason and "(0196, 0164)" in reason
    reason = jail.install_reason(["cargo", "build"], frozenset)
    assert reason is not None and "(cargo fetch --locked)" in reason


def test_a_yarn_refusal_names_the_script_form() -> None:
    # 0196: only yarn refusals carry the script form.
    reason = jail.install_reason(["yarn", "--silent", "build"], frozenset)
    assert reason is not None and reason.endswith(jail.R_YARN_SCRIPT)
    other = jail.install_reason(["npm", "install"], frozenset)
    assert other is not None and jail.R_YARN_SCRIPT not in other


def test_an_unusable_manifest_enables_no_install(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "service-manifest.json").write_text('{"dependencies": {"installs": ["ruby"]}}')
    with pytest.raises(ManifestError, match="dependencies.installs"):
        load_manifest(repo)
    assert _judge("coder", "npm ci --ignore-scripts", repo) is not None


@pytest.mark.parametrize(
    "block",
    [[], {"installs": "npm"}, {"installs": ["npm", "npm"]}, {"installs": [1]}, {"install": []}],
)
def test_the_installs_key_refuses_a_bad_shape(block: object, tmp_path: Path) -> None:
    (tmp_path / "service-manifest.json").write_text(json.dumps({"dependencies": block}))
    with pytest.raises(ManifestError, match="dependencies"):
        load_manifest(tmp_path)


def test_the_installs_key_reads_in_order(tmp_path: Path) -> None:
    (tmp_path / "service-manifest.json").write_text('{"dependencies": {"installs": ["go", "npm"]}}')
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.dependencies.installs == ("go", "npm")


def test_the_kernel_wrapper_check_never_admits_an_install() -> None:
    # 0196, 228 S3b: the confine check refuses an install by its grammar, never as a test.
    flags = confine.PARSER.parse_args([])
    for command in ("pnpm install --frozen-lockfile --ignore-scripts", "uv sync --frozen"):
        got = confine.judge(_b("coder", command), flags)
        assert got is not None and "Refused: " in got, command
    got = confine.judge(_b("coder", "pnpm test"), flags)
    assert got is not None and "Refused: " not in got
