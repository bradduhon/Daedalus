# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0186, 0189: the golden set under evals/ is valid without running any model.
# Key sets mirror the case schema of the Claude Code eval harness (2.1.305); frontmatter values
# are written as JSON so this test needs no YAML parser, and PyYAML cross-checks when present.
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EVALS = REPO_ROOT / "evals"
FIXTURES = EVALS / "fixtures"
CASES = (
    "small-fix",
    "contract-build",
    "terraform-change",
    "dependency-bump",
    "contract-question",
    "security-defect",
    "verify-refutes",
    "folder-scope",
    "document-phase",
    "release-stops-before-push",
)
# 0190: the agent names the suite may carry; the old names never appear under evals/.
AGENTS = frozenset(
    {"coder", "verifier", "auditor", "writer", "comparer", "releaser", "orchestrator"}
)
OLD_NAMES = (
    "repo-coder",
    "security-auditor",
    "pr-train-conductor",
    "docs-writer",
    "doc-deriver",
    "change-logger",
)
# 0189: one tag per fold or comparison the set measures.
FOLDS = frozenset(
    {
        "fold-standards",
        "fold-contract",
        "fold-planner",
        "fold-web",
        "fold-judges",
        "fold-orchestrator",
        "model-coder",
    }
)
TOP_KEYS = frozenset(
    {"schema_version", "name", "description", "tags", "plugins", "runs", "expected_outcome"}
)
EXEC_KEYS = frozenset(
    {
        "model",
        "max_turns",
        "timeout_seconds",
        "allowed_tools",
        "disallowed_tools",
        "artifact_publish",
        "growthbook_overrides",
        "append_system_prompt",
        "env",
    }
)
GRADER_COMMON = frozenset({"type", "name", "weight", "arm"})
GRADER_KEYS: dict[str, frozenset[str]] = {
    "regex": frozenset({"target", "pattern", "flags", "match"}),
    "tool_order": frozenset({"before", "after"}),
    "tool_used": frozenset({"tool", "input_match", "min", "max"}),
    "file_exists": frozenset({"path", "exists"}),
    "llm": frozenset({"criteria", "focus"}),
    "baseline": frozenset({"baseline_file", "criteria"}),
}
# Keys a grader body fills when the frontmatter leaves them out.
BODY_KEY = {"regex": "pattern", "llm": "criteria", "baseline": "criteria"}
REQUIRED: dict[str, tuple[str, ...]] = {
    "regex": ("pattern",),
    "tool_order": ("before", "after"),
    "tool_used": ("tool",),
    "file_exists": ("path",),
    "llm": ("criteria",),
    "baseline": ("baseline_file", "criteria"),
}
TARGETS = frozenset({"trace", "last_message", "files", "mock_calls"})
CONTEXT_KEYS = frozenset({"scaffold_script", "history_file", "add_dirs"})
CASE_YAML_KEYS = TOP_KEYS | {"context", "execution", "graders"}
SHIM = (
    "# Copyright (c) 2026 Brad Duhon.\n"
    "# SPDX-License-Identifier: GPL-3.0-or-later\n"
    "# 0186: the harness runs this with bash in the eval workspace; scaffold.py stages the "
    "fixture.\n"
    "set -eu\n"
    'here=$(cd "$(dirname "$0")" && pwd)\n'
    'exec python3 "$here/../scaffold.py" "$(basename "$here")"\n'
)
PLAN_PROMPT = re.compile(r"^/daedalus:run (plans/\S+\.md)$")
# 0186: inputs a prompt names must ship in its fixture; outputs such as out/faq.md need not.
NAMED_INPUT = re.compile(r"\b((?:plans|specs|sources|contracts)/[\w.-]+\.md)")
# Plugin text a session reads into its trace; a trace grader must not be decided by it.
PLUGIN_TEXT = ("agents", "skills", "hooks", "scripts", "packs", "docs/howto")
PLUGIN_FILES = ("README.md", "docs/guardrails.md", "docs/project-requirements.md")


def _json_lines(text: str, where: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, raw = line.partition(": ")
        assert sep and key.isidentifier(), f"{where}: not a 'key: <json>' line: {line!r}"
        assert key not in out, f"{where}: duplicate key {key}"
        # A bare word is a YAML plain string, such as type: regex.
        bare = re.fullmatch(r"[a-z_][a-z_-]*", raw) and raw not in {"true", "false", "null"}
        out[key] = raw if bare else json.loads(raw)
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return out
    assert yaml.safe_load(text) == out, f"{where}: YAML and JSON readings differ"
    return out


def _split(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path}: no frontmatter"
    head, sep, body = text[4:].partition("\n---\n")
    assert sep, f"{path}: unterminated frontmatter"
    return _json_lines(head, str(path)), body.strip()


def _js_regex(pattern: str, where: str) -> None:
    # Graders run as JS RegExp; inline flags like (?i) are Python-only.
    assert not re.search(r"\(\?[A-Za-z]", pattern), f"{where}: inline regex flag"
    re.compile(pattern)


def _load_scaffold() -> ModuleType:
    spec = importlib.util.spec_from_file_location("golden_scaffold", EVALS / "scaffold.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ten_cases() -> None:
    found = sorted(p.parent.name for p in EVALS.glob("*/prompt.md"))
    assert found == sorted(CASES)


@pytest.mark.parametrize("case", CASES)
def test_prompt_frontmatter(case: str) -> None:
    fm, body = _split(EVALS / case / "prompt.md")
    assert set(fm) <= TOP_KEYS | EXEC_KEYS, set(fm) - (TOP_KEYS | EXEC_KEYS)
    assert fm["name"] == case
    assert fm["runs"] == 2
    assert isinstance(fm.get("description"), str) and fm["description"]
    tags = fm["tags"]
    assert isinstance(tags, list) and tags and len(tags) == len(set(tags))
    assert set(tags) <= AGENTS | FOLDS, set(tags) - (AGENTS | FOLDS)
    assert isinstance(fm["max_turns"], int) and 1 <= fm["max_turns"] <= 200
    assert isinstance(fm["timeout_seconds"], int) and 1 <= fm["timeout_seconds"] <= 3600
    tools = fm["allowed_tools"]
    assert isinstance(tools, list) and all(isinstance(t, str) and t for t in tools)
    for key in ("model", "append_system_prompt"):
        assert key not in fm or (isinstance(fm[key], str) and fm[key])
    env = fm.get("env", {})
    assert isinstance(env, dict)
    assert all(k.startswith("EVAL_") and isinstance(v, str) for k, v in env.items())
    assert body, "prompt.md has no prompt"


@pytest.mark.parametrize("case", CASES)
def test_graders(case: str) -> None:
    files = sorted((EVALS / case / "graders").glob("*.md"))
    assert files, f"{case}: no graders"
    for path in files:
        fm, body = _split(path)
        kind = fm.get("type")
        assert kind in GRADER_KEYS, f"{path}: type {kind!r}"
        assert set(fm) <= GRADER_COMMON | GRADER_KEYS[kind], f"{path}: {set(fm)}"
        if kind in BODY_KEY and BODY_KEY[kind] not in fm and body:
            fm[BODY_KEY[kind]] = body
        for key in REQUIRED[kind]:
            assert isinstance(fm.get(key), str) and fm[key], f"{path}: needs {key}"
        assert fm.get("weight", 1) > 0
        assert fm.get("arm", "both") in {"with-only", "both"}
        for key in ("target", "focus"):
            if key in fm:
                value = fm[key]
                assert (isinstance(value, dict) and value.get("source") == "file") or (
                    value in TARGETS
                ), f"{path}: {key}"
        if kind == "regex":
            match = fm.get("match", "contains")
            assert match in {"contains", "not_contains"} or re.fullmatch(r"count:\d+", match)
            assert re.fullmatch(r"[dgimsuvy]*", fm.get("flags", ""))
            _js_regex(fm["pattern"], str(path))
        if kind == "tool_used":
            if "input_match" in fm:
                _js_regex(fm["input_match"], str(path))
            low, high = fm.get("min", 1), fm.get("max")
            assert isinstance(low, int) and low >= 0
            assert high is None or (isinstance(high, int) and low <= high)
        if kind == "file_exists":
            assert isinstance(fm.get("exists", True), bool)


@pytest.mark.parametrize("case", CASES)
def test_case_yaml(case: str) -> None:
    data = _json_lines((EVALS / case / "case.yaml").read_text(encoding="utf-8"), case)
    assert set(data) <= CASE_YAML_KEYS
    version = data["schema_version"]
    assert isinstance(version, str) and int(version.split(".")[0]) <= 1
    assert data["name"] == case
    context = data["context"]
    assert isinstance(context, dict) and set(context) <= CONTEXT_KEYS
    assert context["scaffold_script"] == "scaffold.sh"


@pytest.mark.parametrize("case", CASES)
def test_pass_rule(case: str) -> None:
    lines = (EVALS / case / "PASS.md").read_text(encoding="utf-8").strip().splitlines()
    assert lines[0].startswith("<!-- Copyright")
    rule = "\n".join(lines[1:]).strip()
    assert rule and "\n\n" not in rule, f"{case}: PASS.md is one paragraph"
    assert len(rule.split()) <= 90


@pytest.mark.parametrize("case", CASES)
def test_fixture(case: str) -> None:
    root = FIXTURES / case
    spec = json.loads((root / "fixture.json").read_text(encoding="utf-8"))
    assert set(spec) == {"git", "origin"} and isinstance(spec["git"], bool)
    assert spec["origin"] is None or str(spec["origin"]).startswith("https://example.invalid/")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["features"]["scope"] == ("repository" if spec["git"] else "folder")
    _, body = _split(EVALS / case / "prompt.md")
    for named in NAMED_INPUT.findall(body):
        assert (root / named).is_file(), (
            f"{case}: the prompt names {named}, absent from the fixture"
        )
    plan = PLAN_PROMPT.match(body)
    if plan:
        done = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate_plan.py"), str(root / plan[1])],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("case", CASES)
def test_scaffold_stages_fixture(case: str, tmp_path: Path) -> None:
    spec = _load_scaffold().stage(case, tmp_path)
    assert (tmp_path / "service-manifest.json").is_file()
    assert (tmp_path / ".claude" / "daedalus" / "config.json").is_file()
    assert (tmp_path / ".claude" / "daedalus" / ".gitignore").read_text() == "*\n"
    assert (tmp_path / ".git").is_dir() is spec["git"]
    if spec["git"]:
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=tmp_path, capture_output=True, text=True
        )
        assert status.stdout == "", status.stdout
    scope = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "daedalus_doctor.py"),
            "--print-scope",
            "--repo",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    want = "repository" if spec["git"] else "folder"
    assert scope.stdout.startswith(f"scope: {want}  root: "), scope.stdout


def _plugin_text() -> list[tuple[str, str]]:
    paths = [REPO_ROOT / name for name in PLUGIN_FILES]
    for folder in PLUGIN_TEXT:
        paths += [p for p in (REPO_ROOT / folder).rglob("*") if p.suffix in {".md", ".py"}]
    out = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        # A trace records file reads as JSON strings, so the escaped form is checked too.
        out += [(str(path), text), (str(path), json.dumps(text))]
    return out


def test_trace_graders_are_not_decided_by_plugin_text() -> None:
    # 0186: a contains grader that plugin text satisfies passes trivially; not_contains fails.
    corpus = _plugin_text()
    for path in sorted(EVALS.glob("*/graders/*.md")):
        fm, body = _split(path)
        if fm.get("type") != "regex" or fm.get("target", "last_message") != "trace":
            continue
        pattern = re.compile(fm.get("pattern", body))
        hits = [where for where, text in corpus if pattern.search(text)]
        assert hits == [], f"{path}: plugin text matches: {hits[:3]}"


def test_agent_names_are_phase_names() -> None:
    # 0190: graders and tags name agents by phase; no file under evals/ carries an old name.
    old = re.compile(r"\b(?:" + "|".join(map(re.escape, OLD_NAMES)) + r")\b")
    for path in EVALS.rglob("*"):
        if path.is_file():
            hit = old.search(path.read_text(encoding="utf-8", errors="replace"))
            assert hit is None, f"{path}: old agent name {hit and hit[0]}"
    named = re.compile(r"\(\?:daedalus:\)\?([a-z-]+)")
    for path in EVALS.glob("*/graders/*.md"):
        for name in named.findall(path.read_text(encoding="utf-8")):
            assert name in AGENTS, f"{path}: {name}"


def test_scaffold_shims() -> None:
    # 0186: the harness runs scaffold_script with bash; the shims are created from the operator's
    # shell because new shell files need the operator's go-ahead.
    missing = [c for c in CASES if not (EVALS / c / "scaffold.sh").is_file()]
    for case in set(CASES) - set(missing):
        assert (EVALS / case / "scaffold.sh").read_text(encoding="utf-8") == SHIM, case
    if missing:
        pytest.skip(f"scaffold.sh not yet created for: {', '.join(missing)}")
