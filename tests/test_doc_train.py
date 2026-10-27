# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0135, 0136, 0137: derived document mode, its two agents and the round skill.
from __future__ import annotations

import json
import re
from pathlib import Path

import freeze_sources
import pytest
from lib import agent_files, router
from lib.agent_files import Hook

from tests.conftest import REPO_ROOT, write_train_marker

# 0174: the doc-train skill is a stub; derived document mode of the document skill holds the recipe.
DOCUMENT = REPO_ROOT / "skills" / "document" / "SKILL.md"
DOC_TRAIN = REPO_ROOT / "skills" / "doc-train" / "SKILL.md"
ROUND = REPO_ROOT / "skills" / "round" / "SKILL.md"
DERIVER = REPO_ROOT / "agents" / "doc-deriver.md"
LOGGER = REPO_ROOT / "agents" / "change-logger.md"
STAGES = ("Preconditions", "Freeze", "Derive", "Verify", "Change gate", "Docs writer", "Present")
FIRST_STEP = 9
_AGENT_REF = re.compile(r"Agent\(`([a-z-]+)`\)")
TRAIN = "20261026-030405"


def _text(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _derived_raw() -> str:
    text = DOCUMENT.read_text(encoding="utf-8")
    return text.split("### Derived document mode\n", 1)[1].split("\n## ", 1)[0]


def _derived() -> str:
    return " ".join(_derived_raw().split())


def _stage(name: str) -> str:
    number = STAGES.index(name) + FIRST_STEP
    body = _derived_raw().split(f"\n{number}. {name}.", 1)[1]
    return " ".join(body.split(f"\n{number + 1}. ", 1)[0].split())


def test_recipe_runs_the_stages_in_order() -> None:
    # 0135: freeze, derive, verify, change gate and present, with the docs writer as a stage.
    heads = re.findall(r"^(\d+)\. ([A-Z][a-z ]+)\.", _derived_raw(), re.M)
    assert heads == [(str(n), name) for n, name in enumerate(STAGES, start=FIRST_STEP)]
    text = _derived()
    assert "This mode is the doc composition, started with `/daedalus:run doc" in text
    assert "No definition file and no runner exist for it." in text


def test_document_skill_holds_the_recipe_the_stub_dropped() -> None:
    # 0174: no shipped skill points at the doc-train text the stub dropped.
    for name in ("document", "run"):
        text = (REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
        assert "doc-train" not in text, name
    assert "The **State Block** of this mode holds:" in _derived()
    assert "/daedalus:run doc" in DOC_TRAIN.read_text(encoding="utf-8")


def test_recipe_dispatches_only_catalog_agents() -> None:
    names = set(_AGENT_REF.findall(_derived_raw()))
    assert names == {
        "standards-rules-specialist",
        "doc-deriver",
        "verifier",
        "change-logger",
        "docs-writer",
    }
    for name in names:
        assert (REPO_ROOT / "agents" / f"{name}.md").is_file(), name
    assert "Agent(`docs-writer`)" in _stage("Docs writer")


def test_recipe_names_the_priorities_section_for_every_agent() -> None:
    # 0137, pin PRIO -> DOCT: the ranking is a brief input for every agent the recipe dispatches.
    text = _derived()
    rule = "every brief, for every agent this recipe dispatches, carries the Standards Packet's"
    assert rule + " `## Priorities` section verbatim as a brief input" in text
    for stage in ("Derive", "Verify", "Change gate", "Docs writer"):
        assert "`## Priorities` section" in _stage(stage), stage


def test_recipe_freezes_and_verifies_through_the_script() -> None:
    freeze = _stage("Freeze")
    form = "scripts/freeze_sources.py --train <train-id> --output-dir <output folder> --source "
    assert form + "<alias>=<role>:<path>[:<topic>,...] ..." in freeze
    assert "add `--baselines-only`" in freeze
    verify = _stage("Verify")
    assert "scripts/freeze_sources.py --verify <repo>/.claude/daedalus/trains/" in verify
    assert "Exit 4: a source changed" in verify and "Exit 5:" in verify
    assert "this is a failed gate" in verify


def test_recipe_marks_the_train_the_output_check_reads() -> None:
    # 0135, D.5: doc_outputs reads the active train id from the YYYYMMDD-HHMMSS marker.
    text = _stage("Preconditions")
    assert "`date -u +%Y%m%d-%H%M%S`" in text
    assert "daedalus_workspace.py mark --repo <repo> --train <train-id>" in text
    assert "daedalus_workspace.py unmark --repo <repo>" in _stage("Present")


def test_recipe_applies_small_findings_and_rechecks_in_claims_mode() -> None:
    # 0136 items 2 and 3, pin VER -> DOCT.
    verify = _stage("Verify")
    assert "a prompt whose first line is `CLAIMS MODE.`" in verify
    assert "one `Claim: <output path>:<line> <claim>` line per claim" in verify
    assert "apply verifier findings of ten lines or fewer yourself" in verify
    assert "send the warm verifier only the edited claims" in verify
    assert "Rounds 2 and 3 read the claims the verifier rejected in the prior round" in verify
    assert "plus a random 20 percent sample of the rest" in verify
    assert "no round budget applies (0133)" in verify
    for choice in ("`Fix it now (Recommended)`", "`Skip, track or exempt it`", "`Stop the run`"):
        assert choice in verify, choice


def test_change_gate_runs_on_a_baseline_and_on_two_baselines() -> None:
    gate = _stage("Change gate")
    assert "only when the manifest declares a `baseline` role" in gate
    assert "With `--baselines-only`, name the two baseline aliases" in gate
    assert '"Baseline says" column only' in gate


def test_recipe_never_pushes_or_stages() -> None:
    text = _derived()
    assert "Zero `git push`, zero `gh`, nothing staged or committed." in text
    assert not re.search(r"`git (add|commit|push) ", text)


def _hooks(path: Path) -> tuple[Hook, ...]:
    return agent_files.load(path).hooks


@pytest.mark.parametrize("path", [DERIVER, LOGGER], ids=lambda p: p.stem)
def test_document_agents_read_only_and_write_only_output(path: Path) -> None:
    # D.5: the read-only Bash check and the document outputs check, git and gh never granted.
    agent = agent_files.load(path)
    assert agent.shape == "producer" and agent.model == "opus"
    assert Hook("read_only_bash", ()) in agent.hooks
    assert Hook("doc_outputs", ()) in agent.hooks
    assert Hook("git_grammar", ()) in agent.hooks
    assert not {"unit_writes", "root_writes", "gh_classes"} & {h.script for h in agent.hooks}
    assert "Write" in agent.tools and not {"WebFetch", "WebSearch"} & agent.tools


def test_change_logger_diffs_two_baselines() -> None:
    # 0136 item 7: no deriver, two baseline aliases, frozen with --baselines-only.
    text = _text(LOGGER)
    assert "`freeze_sources.py --baselines-only`" in text
    assert "When the manifest carries two `baseline` aliases, no deriver ran" in text
    assert "Never `agreed` without a citation." in text
    assert "Edit" not in agent_files.load(LOGGER).tools


def test_deriver_returns_claims_for_the_verifier() -> None:
    text = _text(DERIVER)
    assert "`Claim: <output path>:<line> <claim> | receipt: <alias>:<line or range>`" in text
    assert "`## Priorities` section (0137)" in text


@pytest.fixture
def doc_repo(git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (git_repo / ".gitignore").write_text("private/\n", encoding="utf-8")
    (git_repo / "private" / "out").mkdir(parents=True)
    (git_repo / "private" / "base.sent-2026-10-01.md").write_text("The fee is 12.\n")
    data = git_repo / ".claude" / "daedalus"
    data.mkdir(parents=True)
    roots = [{"kind": "path", "path": "<repo_root>/private/"}]
    (data / "config.json").write_text(json.dumps({"excluded_roots": roots}), encoding="utf-8")
    monkeypatch.chdir(git_repo)
    source = ["--source", "A=baseline:private/base.sent-2026-10-01.md"]
    assert freeze_sources.main(["--train", TRAIN, "--output-dir", "private/out", *source]) == 0
    write_train_marker(git_repo, TRAIN)
    return git_repo


def _call(repo: Path, agent: str, tool: str, **fields: str) -> tuple[bool, str | None, str]:
    payload = {"agent_type": f"daedalus:{agent}", "tool_name": tool, "tool_input": fields}
    return router.route({**payload, "cwd": str(repo)}, REPO_ROOT)


@pytest.mark.parametrize("agent", ["doc-deriver", "change-logger"])
def test_routed_document_agent_writes_only_in_the_output_folder(doc_repo: Path, agent: str) -> None:
    inside = str(doc_repo / "private" / "out" / "doc.md")
    assert _call(doc_repo, agent, "Write", file_path=inside, content="x") == (True, None, "")
    allow, _, hook = _call(doc_repo, agent, "Write", file_path=str(doc_repo / "a.md"), content="x")
    assert (allow, hook) == (False, "doc_outputs")
    source = str(doc_repo / "private" / "base.sent-2026-10-01.md")
    allow, reason, hook = _call(doc_repo, agent, "Write", file_path=source, content="x")
    assert (allow, hook) == (False, "doc_outputs") and "is source A" in str(reason)
    assert not _call(doc_repo, agent, "Bash", command="git status")[0]
    assert _call(doc_repo, agent, "Bash", command=f"wc -l {source}")[0]


def test_round_skill_logs_holds_and_flips_on_the_operators_word() -> None:
    # 0136 item 1, D.8: the bookkeeping half of correspondence; never drafts or sends.
    text = _text(ROUND)
    for action in ("`inbound`", "`draft`", "`edit`", "`sent`"):
        assert f"{action}:" in text, action
    assert "the text verbatim inside a fenced block, unchanged" in text
    assert "`Status: RECEIVED <time>`" in text and "`Status: SENT <time>`" in text
    assert "only on the operator's own words in this conversation that the reply went out" in text
    assert "You never make an edit the operator did not name." in text
    assert "never send anything" in text
