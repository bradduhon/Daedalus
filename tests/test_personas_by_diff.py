# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0132, 0134: the dependency auditor, the Terraform reviewer, the docs writer and their keys.
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from lib.agent_files import Hook, load
from lib.manifest import (
    FEATURE_KEYS,
    LITERACY_LEVELS,
    Docs,
    Features,
    ManifestError,
)
from lib.manifest import load as load_manifest
from lib.project_keys import (
    KEY_ROWS,
    LITERACY_EXAMPLES,
    MANIFEST_FILE,
    manifest_keys,
    starter_manifest,
)
from lib.train_summary import SessionLog, parse_notes, render

from tests.conftest import CFG, CWD, REPO_ROOT
from tests.hook_chain import first_deny
from tests.test_train_state_print import NOTES, RECORDS, REPO, STATE, TRAIN, _section, _stop

AGENTS = REPO_ROOT / "agents"
JUDGES = ("dependency-auditor", "terraform-reviewer")
FOUR_DOCS = (
    "`README.md`",
    "`docs/howto/README.md`",
    "`docs/guardrails.md`",
    "`docs/project-requirements.md`",
)
PER_FINDING = "`Exempt the finding`, `Run a fix round` and `End the train`"
VERIFIER_DESCRIPTION = (
    "Adversarial read-only verifier of one unit's diff against its brief. Judges what the unit "
    "did, did not do, added or subtracted against its requirements; agreement earns nothing."
)


def _write(repo: Path, payload: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


# Manifest keys (requirement 4).


def test_persona_switches_follow_github_in_the_feature_list() -> None:
    assert FEATURE_KEYS[FEATURE_KEYS.index("github") + 1 :] == (
        "dependency_web_lookup",
        "terraform_tools",
    )
    assert Features().dependency_web_lookup is None and Features().terraform_tools is None


@pytest.mark.parametrize("key", ["dependency_web_lookup", "terraform_tools"])
@pytest.mark.parametrize("value", [True, False, None])
def test_persona_switch_reads_true_false_or_null(
    tmp_path: Path, key: str, value: bool | None
) -> None:
    _write(tmp_path, {"features": {key: value}})
    loaded = load_manifest(tmp_path)
    assert loaded is not None and getattr(loaded.features, key) is value


@pytest.mark.parametrize("key", ["dependency_web_lookup", "terraform_tools"])
@pytest.mark.parametrize("value", ["off", 0, 1, [], {}])
def test_persona_switch_refuses_a_value_outside_its_type(
    tmp_path: Path, key: str, value: object
) -> None:
    _write(tmp_path, {"features": {key: value}})
    with pytest.raises(ManifestError, match=f"features.{key} must be true, false or null"):
        load_manifest(tmp_path)


@pytest.mark.parametrize(
    "value", [None, *LITERACY_LEVELS, "profile:docs/voice.md", "profile:voice.md"]
)
def test_docs_literacy_reads_a_level_a_profile_or_null(tmp_path: Path, value: str | None) -> None:
    _write(tmp_path, {"docs": {"literacy": value}})
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.docs == Docs(value)


def test_absent_docs_block_reads_null_literacy(tmp_path: Path) -> None:
    _write(tmp_path, {})
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.docs == Docs() and loaded.docs.literacy is None


@pytest.mark.parametrize(
    "value",
    [
        "fancy",
        "",
        "PLAIN",
        "profile:",
        "profile:/etc/voice.md",
        "profile:../voice.md",
        "profile:docs/*.md",
        "profile:a\\b",
        3,
        True,
        ["plain"],
    ],
)
def test_docs_literacy_refuses_any_other_value(tmp_path: Path, value: object) -> None:
    _write(tmp_path, {"docs": {"literacy": value}})
    with pytest.raises(ManifestError, match="docs.literacy must be null") as caught:
        load_manifest(tmp_path)
    assert str(caught.value).count("Next:") == 1


@pytest.mark.parametrize("payload", [{"docs": []}, {"docs": "plain"}, {"docs": {"voice": "x"}}])
def test_docs_block_refuses_a_wrong_shape_or_unknown_key(tmp_path: Path, payload: object) -> None:
    _write(tmp_path, payload)
    with pytest.raises(ManifestError, match=r"docs (must be an object|has unknown keys)"):
        load_manifest(tmp_path)


def test_key_reference_rows_cover_the_three_keys_in_order() -> None:
    keys = manifest_keys()
    github = keys.index("features.github")
    assert keys[github + 1 : github + 3] == (
        "features.dependency_web_lookup",
        "features.terraform_tools",
    )
    assert keys.index("docs.literacy") == keys.index("stack.lint_cmd") + 1
    for key in ("features.dependency_web_lookup", "features.terraform_tools", "docs.literacy"):
        assert (MANIFEST_FILE, key) in KEY_ROWS, key


def test_starter_manifest_writes_the_docs_block_and_every_example_loads(tmp_path: Path) -> None:
    starter = starter_manifest()
    assert starter["docs"] == {"literacy": None}
    features = starter["features"]
    assert isinstance(features, dict)
    assert features["dependency_web_lookup"] is False and features["terraform_tools"] is False
    for example in LITERACY_EXAMPLES:
        _write(tmp_path, {"docs": {"literacy": json.loads(example)}})
        loaded = load_manifest(tmp_path)
        assert loaded is not None and loaded.docs.literacy == json.loads(example)


# Agent files (requirements 1 to 3 and 8).


def test_judges_are_read_only_off_the_network_and_carry_the_verifier_read_list() -> None:
    verifier = load(AGENTS / "verifier.md")
    # 0109: the test-runner grant stays with the verifier; a judge here runs no tests.
    want = tuple(
        Hook(h.script, ("--git", "read-only")) if h.script == "read_only_bash" else h
        for h in verifier.hooks
    )
    for name in JUDGES:
        judge = load(AGENTS / f"{name}.md")
        assert judge.shape == "judge", name
        assert judge.tools == frozenset({"Read", "Grep", "Glob", "Bash"}), name
        assert judge.hooks == want, name
        assert judge.status_lines[-1].startswith("[STATUS: COMPLIANCE] <PASS/FAIL list"), name


def test_dependency_auditor_asks_for_advisories_only_through_a_web_yield() -> None:
    auditor = load(AGENTS / "dependency-auditor.md")
    assert auditor.status_lines == (
        "[STATUS: YIELD_WEB] <query>",
        "[STATUS: COMPLIANCE] <PASS/FAIL list with rule ids and file:line>",
    )
    text = _flat(AGENTS / "dependency-auditor.md")
    for phrase in (
        "dependency manifest or a lockfile",
        "You are off the network.",
        "`Web lookup: off`",
        "`[STATUS: YIELD_WEB] <ecosystem> <name> <version> security advisories`",
        "Never run a package manager",
    ):
        assert phrase in text, phrase


def test_terraform_reviewer_checks_the_binary_before_any_tool_run() -> None:
    text = _flat(AGENTS / "terraform-reviewer.md")
    binary = text.index("## Binary check (before any tool run)")
    method = text.index("## Method")
    assert binary < method
    assert "-maxdepth 1 -name terraform`" in text[binary:method]
    assert "A missing binary is a warning, never a FAIL" in text[binary:method]
    for phrase in ("`terraform fmt -check`", "`terraform validate`", "`Terraform tools: off`"):
        assert phrase in text, phrase
    assert "Never run `init`, `plan`, `apply`" in text


def test_docs_writer_edits_only_the_four_docs_and_claims_each_passage() -> None:
    writer = load(AGENTS / "docs-writer.md")
    coder = load(AGENTS / "repo-coder.md")
    assert writer.shape == "producer" and writer.hooks == coder.hooks
    assert writer.status_lines == (
        "[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>",
        "[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>",
    )
    text = _flat(AGENTS / "docs-writer.md")
    scope = text[text.index("## Scope") : text.index("## Method")]
    for doc in FOUR_DOCS:
        assert doc in scope, doc
    assert "`docs.literacy`" in text and "unless the brief overrides it" in text
    assert "`Claim: <doc path>:<line> <what the passage now says> | receipt: <command>`" in text
    assert "hand-back summary" in text and "diff" in text


def test_verifier_description_is_the_pin_text() -> None:
    assert load(AGENTS / "verifier.md").description == VERIFIER_DESCRIPTION


@pytest.mark.parametrize(
    ("agent", "tool", "tool_input"),
    [
        ("dependency-auditor", "WebFetch", {"url": "https://example.invalid/advisory"}),
        ("dependency-auditor", "Bash", {"command": "curl https://example.invalid/advisory"}),
        ("dependency-auditor", "Write", {"file_path": f"{CWD}/package.json", "content": "x"}),
        ("terraform-reviewer", "Bash", {"command": "terraform apply -auto-approve"}),
        ("terraform-reviewer", "Edit", {"file_path": f"{CWD}/main.tf"}),
    ],
)
def test_judge_chains_refuse_writes_fetches_and_changes(
    jail_fakes: None, agent: str, tool: str, tool_input: dict[str, str]
) -> None:
    hook_input: dict[str, object] = {
        "agent_type": f"daedalus:{agent}",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": CWD,
    }
    assert first_deny(hook_input, CFG) is not None


# Orchestrator wiring (requirements 5 and 6).


def _orchestrator() -> str:
    return (AGENTS / "orchestrator.md").read_text(encoding="utf-8")


def test_phase_3_step_2_consults_both_judges_by_diff_content() -> None:
    text = _orchestrator()
    step2 = text[text.index("2. Policy gate:") : text.index("3. SendMessage(standards specialist")]
    flat = " ".join(step2.split())
    for phrase in (
        "Consults by diff content (0132), beside the standards specialists",
        "Agent(`dependency-auditor`)",
        "Agent(`terraform-reviewer`)",
        "`.tf` or `.tfvars`",
        "`features.dependency_web_lookup` is `false`",
        "`features.terraform_tools` is `false`",
        "The reviewer checks for the terraform binary itself.",
        "[STATUS: YIELD_WEB] <query>",
        "never the audit gate",
        f"through the per-finding step of Phase 3, one decision question per FAIL with the "
        f"options {PER_FINDING}",
    ):
        assert phrase in flat, phrase


def test_documentation_stage_sits_directly_before_recovery() -> None:
    text = _orchestrator()
    headings = re.findall(r"^## .+$", text, re.M)
    assert headings.index("## Documentation stage") + 1 == headings.index("## Recovery")
    stage = text[text.index("## Documentation stage") : text.index("## Recovery")]
    flat = " ".join(stage.split())
    for phrase in (
        "after the security verdict record",
        "--name <train-id>-docs --base daedalus/<train-id>",
        "Agent(`docs-writer`)",
        "the hand-back summary of every unit whose agent changed something",
        "the line `Worktree: <docs worktree path>`",
        "the first line `CLAIMS MODE.`",
        "`Claim: <doc path>:<line> <claim>`",
        "`docs.literacy`",
        f"one decision question per refuted claim with the options {PER_FINDING}",
    ):
        assert phrase in flat, phrase
    for doc in FOUR_DOCS:
        assert doc in flat, doc


# Train summary (requirement 7).


def test_judge_lists_join_the_compliance_section(tmp_path: Path) -> None:
    records = [
        *RECORDS,
        _stop(10, "dependency-auditor", "[STATUS: COMPLIANCE] DEP-1 PASS, DEP-5 PASS", "d1"),
        _stop(11, "terraform-reviewer", "[STATUS: COMPLIANCE] TF-0 WARN, TF-3 PASS", "t1"),
        _stop(12, "dependency-auditor", "[STATUS: YIELD_WEB] npm left-pad 1.3.0 advisories", "d1"),
    ]
    log = SessionLog("sess-a", tmp_path / "sess-a.jsonl", records)
    text = render(REPO, TRAIN, STATE, [log], parse_notes(NOTES, "notes"), False, None)
    assert _section(text, "Compliance") == [
        "- nist-specialist: AU-9 PASS, AU-3 PASS",
        "- dependency-auditor: DEP-1 PASS, DEP-5 PASS",
        "- terraform-reviewer: TF-0 WARN, TF-3 PASS",
    ]
    assert "DEP-1" not in "\n".join(_section(text, "Audit"))
