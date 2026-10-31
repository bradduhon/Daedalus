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
PUBLIC_DOCS_KIND = REPO_ROOT / "skills" / "document" / "kinds" / "public-docs" / "SKILL.md"
JUDGES = ("dependency-auditor", "terraform-reviewer")
FOUR_DOCS = (
    "`README.md`",
    "`docs/howto/README.md`",
    "`docs/guardrails.md`",
    "`docs/project-requirements.md`",
)
PER_FINDING = "`Fix it now (Recommended)`, `Skip, track or exempt it` and `Stop the run`"
VERIFIER_DESCRIPTION = (
    "Adversarial read-only verifier of one unit's diff against its brief. Judges what the unit "
    "did, did not do, added or subtracted against its requirements; agreement earns nothing."
)


def _write(repo: Path, payload: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


# Manifest keys (requirement 4).


def test_persona_switches_follow_ledger_in_the_feature_list() -> None:
    assert FEATURE_KEYS[FEATURE_KEYS.index("ledger") + 1 :] == (
        "dependency_web_lookup",
        "terraform_tools",
        "terraform_validate",
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
    ledger = keys.index("features.ledger")
    assert keys[ledger + 1 : ledger + 3] == (
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
    # 0132: the reviewer's read list is the inspect class plus the terraform class (JAIL).
    terraform = Hook("command_allowlist", ("--allow", "terraform,inspect"))
    for name in JUDGES:
        judge = load(AGENTS / f"{name}.md")
        assert judge.shape == "judge", name
        assert judge.tools == frozenset({"Read", "Grep", "Glob", "Bash"}), name
        if name == "terraform-reviewer":
            assert judge.hooks == tuple(
                terraform if h.script == "read_only_bash" else h for h in want
            ), name
        else:
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


# 0189, 0192: the npm rows live in a rulebook file the audit dispatch names, never the agent body.
NPM_RULEBOOK = REPO_ROOT / "packs" / "dependencies" / "npm.md"
RULE_ROW = re.compile(r"^- (DEP-[A-Z0-9-]+): (\S.*)$")


def _rule_rows(text: str) -> list[str]:
    rows = text.split("\n## Rows\n", 1)[1].split("\n## ", 1)[0]
    return [m.group(1) for line in rows.splitlines() if (m := RULE_ROW.match(line))]


def test_npm_rulebook_parses_to_the_row_shape_the_auditor_judges() -> None:
    agent_rows = _rule_rows((AGENTS / "dependency-auditor.md").read_text(encoding="utf-8"))
    assert agent_rows == [f"DEP-{n}" for n in range(1, 8)]
    text = NPM_RULEBOOK.read_text(encoding="utf-8")
    assert text.startswith("<!-- Copyright (c) 2026 Brad Duhon.")
    assert _rule_rows(text) == [f"DEP-NPM-{n}" for n in range(1, 5)]
    body = text.split("\n## Rows\n", 1)[1]
    assert all(line.startswith("- DEP-NPM-") for line in body.strip().splitlines())
    for phrase in ("`git+`", "`file:`", "`postinstall`", "`minimumReleaseAge`"):
        assert phrase in text, phrase
    assert "DEP-NPM" not in (AGENTS / "dependency-auditor.md").read_text(encoding="utf-8")
    assert "When the dispatch carries a `Rulebook: <path>` line, Read that file" in _flat(
        AGENTS / "dependency-auditor.md"
    )


def test_audit_dispatch_names_the_npm_rulebook_when_an_npm_file_changed() -> None:
    text = _phase("audit")
    step = " ".join(text.split("dispatch `dependency-auditor`", 1)[1].split("\n", 1)[0].split())
    assert (
        "`Rulebook: ${CLAUDE_PLUGIN_ROOT}/packs/dependencies/npm.md` when the diff names "
        "`package.json`, `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`"
    ) in step


def test_dependency_auditor_may_read_the_npm_rulebook(jail_fakes: None) -> None:
    hook_input: dict[str, object] = {
        "agent_type": "daedalus:dependency-auditor",
        "tool_name": "Read",
        "tool_input": {"file_path": str(NPM_RULEBOOK)},
        "cwd": CWD,
    }
    assert first_deny(hook_input, CFG) is None


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


def test_public_docs_writer_edits_only_the_four_docs_and_claims_each_passage() -> None:
    writer = load(AGENTS / "writer.md")
    coder = load(AGENTS / "coder.md")
    # 0134: the coder's list, with the write check narrowed by --docs (JAIL).
    narrowed = tuple(
        Hook(h.script, ("--docs",)) if h.script == "unit_writes" else h for h in coder.hooks
    )
    # 0190: the public docs kind of the writer runs that list; its kind skill holds the method.
    assert writer.shape == "producer" and writer.chains()["public-docs"] == narrowed
    assert writer.status_lines[:2] == (
        "[STATUS: DOCS_WRITTEN] branch=<b> commit=<40 hex> claims=<n>",
        "[STATUS: DOCS_UNCHANGED] reason=<why no passage needed an edit>",
    )
    text = _flat(PUBLIC_DOCS_KIND)
    assert all(f"`{line}`" in text for line in writer.status_lines[:2])
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


def _phase(name: str) -> str:
    # 0165: the orchestrator reads and runs each phase from its skill.
    return (REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")


# 0169: the phase skills and the catalog share one label set, all saying run.
PER_FINDING_RUN = PER_FINDING


def test_phase_3_step_2_consults_both_judges_by_diff_content() -> None:
    text = _phase("audit")
    step2 = text[text.index("1. Policy gate:") : text.index("### Auditor rounds")]
    flat = " ".join(step2.split())
    rejected = " ".join(text.split("\n8. Per-finding step.", 1)[1].split("\n9. ", 1)[0].split())
    assert f"with the choices {PER_FINDING_RUN}" in rejected
    for phrase in (
        "Consults by diff content (0132), beside the standards specialists",
        "dispatch `dependency-auditor`",
        "dispatch `terraform-reviewer`",
        "`.tf` or `.tfvars`",
        "`features.dependency_web_lookup` is `false`",
        "`features.terraform_tools` is `false`",
        "The reviewer checks for the terraform binary itself.",
        "[STATUS: YIELD_WEB] <query>",
        "never the audit gate",
        "through the per-finding step below, one decision question per FAIL",
    ):
        assert phrase in flat, phrase


def test_documentation_stage_sits_directly_before_recovery() -> None:
    # 0165: the orchestrator runs the document phase after the audit, before any recovery round.
    text = _orchestrator()
    phases = text[text.index("## Phases") : text.index("## Recovery")]
    audit = phases.index("Read and run `<plugin root>/skills/audit/SKILL.md`")
    assert audit < phases.index("Read and run `<plugin root>/skills/document/SKILL.md`")
    doc = _phase("document")
    stage = doc[doc.index("### Public docs mode") : doc.index("### Derived document mode")]
    flat = " ".join(stage.split())
    for phrase in (
        "after the security verdict record",
        "--name <train-id>-docstage --base daedalus/<train-id>",
        "dispatch `writer`",
        "the hand-back summary of every unit whose agent changed something",
        "the line `Worktree: <docs worktree path>`",
        "the first line `CLAIMS MODE.`",
        "`Claim: <doc path>:<line> <claim>`",
        "`docs.literacy`",
        f"one decision question per refuted claim with the options {PER_FINDING_RUN}",
    ):
        assert phrase in flat, phrase
    for name in FOUR_DOCS:
        assert name in flat, name


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
        "- framework-specialist: AU-9 PASS, AU-3 PASS",
        "- dependency-auditor: DEP-1 PASS, DEP-5 PASS",
        "- terraform-reviewer: TF-0 WARN, TF-3 PASS",
    ]
    assert "DEP-1" not in "\n".join(_section(text, "Audit"))
