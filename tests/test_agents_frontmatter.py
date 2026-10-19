# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from pathlib import Path

import pytest
from lib import hook_io, router
from lib.agent_files import PHASES, Hook, frontmatter, load
from lib.config import Config
from lib.jail import WORKER_DENIED_TOOLS
from lib.train_scope import KNOWN_AGENTS

from tests.conftest import REPO_ROOT

AGENTS = REPO_ROOT / "agents"
EXPECTED_MODEL = {
    "repo-coder": "opus",
    "security-auditor": "opus",
    "pr-train-conductor": "opus",
    "contract-spec": "sonnet",
    "charter-docs": "sonnet",
    "nist-specialist": "sonnet",
    "cis-specialist": "sonnet",
    "standards-rules-specialist": "sonnet",
    "web-researcher": "haiku",
    "planner": "opus",
}
# 0089: phase affinities guide the session's choice of agent; they never gate a phase.
EXPECTED_PHASES = {
    "repo-coder": ("implementation",),
    "security-auditor": ("audit",),
    "contract-spec": ("clarification", "plan"),
    "standards-rules-specialist": ("clarification", "plan"),
    "charter-docs": ("clarification", "commit", "release"),
    "pr-train-conductor": ("commit", "release"),
    "nist-specialist": ("clarification", "audit"),
    "cis-specialist": ("clarification", "audit"),
    "web-researcher": ("context",),
    "planner": ("plan",),
}


def _list(value: str, path: Path) -> set[str]:
    assert not set("[]\"'") & set(value), f"{path}: flow list or quoted value in frontmatter"
    return {item.strip() for item in value.split(",") if item.strip()}


def test_every_known_worker_has_a_persona_and_no_extras() -> None:
    names = {p.stem for p in AGENTS.glob("*.md")}
    assert names == KNOWN_AGENTS - {"main"}
    assert names == set(EXPECTED_MODEL) == set(EXPECTED_PHASES)


@pytest.mark.parametrize("name", sorted(EXPECTED_PHASES))
def test_every_agent_has_known_phases(name: str) -> None:
    # 9.1: the phases key lists affinities in phase order, each a known phase token.
    path = AGENTS / f"{name}.md"
    phases = load(path).phases
    assert phases == EXPECTED_PHASES[name]
    assert set(phases) <= set(PHASES)
    assert list(phases) == sorted(phases, key=PHASES.index)
    assert frontmatter(path)["phases"] == f"[{', '.join(phases)}]"


PLANNER = AGENTS / "planner.md"


def test_planner_frontmatter_and_reply_lines() -> None:
    # spec 3.1: a shaper that reads and writes exactly one plan file under the train scratch.
    planner = load(PLANNER)
    assert planner.shape == "shaper" and planner.model == "opus"
    assert planner.tools == frozenset({"Read", "Grep", "Glob", "Write"})
    assert planner.hooks == (
        Hook("credential_paths", ()),
        Hook("workspace_integrity", ()),
        Hook("tool_bound", ()),
        Hook("root_writes", ("--touch", "scratch", "--name", "plan.md")),
    )
    assert planner.status_lines == (
        "[STATUS: PLAN] path=<path> units=<n> critical_path=<k> width=<w>",
        "[STATUS: QUESTION] <what the task leaves open>",
    )
    disallowed = _list(frontmatter(PLANNER)["disallowedTools"], PLANNER)
    assert {"Edit", "Bash", "WebFetch", "WebSearch", "Agent", "Task", "SendMessage"} <= disallowed
    text = " ".join(PLANNER.read_text(encoding="utf-8").split())
    for rule in (
        "Cut into bodies that touch non-overlapping file areas",
        "Name every edge's kind",
        "Prefer an interface pin over a file overlap",
        "A pin is never an edge.",
        "`max_concurrent_builders`",
        "`wire: none`",
    ):
        assert rule in text, rule
    assert "```plan" in text


@pytest.mark.parametrize("name", sorted(EXPECTED_MODEL))
def test_frontmatter_matches_rulings(name: str) -> None:
    path = AGENTS / f"{name}.md"
    fm = frontmatter(path)
    assert fm["name"] == name
    assert fm["model"] == EXPECTED_MODEL[name]
    assert fm["description"]
    tools = _list(fm["tools"], path)
    assert tools, "tools must be explicit (spec 4.1)"
    assert not (tools & WORKER_DENIED_TOOLS)
    assert "memory" not in fm
    disallowed = _list(fm.get("disallowedTools", ""), path)
    assert {"Agent", "Task", "SendMessage"} <= disallowed


def test_repo_coder_works_in_the_train_made_worktree() -> None:
    # 0022: the Build Train makes the worktree; Claude Code isolation is off.
    assert "isolation" not in frontmatter(AGENTS / "repo-coder.md")
    text = (AGENTS / "repo-coder.md").read_text()
    assert "`Worktree: <path>`" in text
    assert '`git -C <path> add -A && git -C <path> commit -m "WIP: yield"`' in text
    assert "`git add -A && git commit" not in text
    # 0022: file paths and git pathspecs are absolute or go through git -C.
    assert "Every file path and every git pathspec you use is absolute" in text


def test_repo_coder_reads_the_packets_by_hash() -> None:
    # 0083: the brief names both packet files with their sha256; COMPLETE echoes 12 hex of each.
    text = " ".join((AGENTS / "repo-coder.md").read_text().split())
    assert "`Contract: <path> sha256=<hex>`" in text
    assert "`Standards: <path> sha256=<hex>`" in text
    assert "refuse to start when a hash does not match" in text
    assert "the injected Locked Contract Packet" not in text
    complete = load(AGENTS / "repo-coder.md").status_lines[-1]
    assert complete.endswith(" contract=<12 hex> standards=<12 hex>")


def test_repo_coder_yields_compliance_before_sensitive_code() -> None:
    # 0024: the compliance yield is expected before sensitive code, not only when blocked.
    text = (AGENTS / "repo-coder.md").read_text()
    raw = text.split("Before writing code that touches", 1)[1].split("\n\n", 1)[0]
    paragraph = " ".join(raw.split())
    for topic in ("authentication", "IAM policy", "key material", "logging of request data"):
        assert topic in paragraph, topic
    assert "`[STATUS: YIELD_COMPLIANCE] <what you are about to write and the question>`" in (
        paragraph
    )
    assert "even when you are not blocked" in paragraph


def test_repo_coder_carries_the_code_hygiene_rule() -> None:
    # 0036: reuse before writing is the coder's standing method, with the security exception.
    text = " ".join((AGENTS / "repo-coder.md").read_text().split())
    assert "Reuse before writing." in text
    assert (
        "The one exception is security: never share or reuse code when doing so widens a"
        " permission, crosses a tenant or trust boundary, or couples a sensitive path to a"
        " general one, and name that exception in the commit message."
    ) in text


@pytest.mark.parametrize("name", sorted(EXPECTED_MODEL))
def test_body_has_header_status_contract_and_no_dashes(name: str) -> None:
    text = (AGENTS / f"{name}.md").read_text()
    after = text.split("---\n", 2)[2]
    assert after.lstrip().startswith(
        "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
    )
    assert "## Status contract" in after
    assert not re.search("[\\u2013\\u2014]", text)
    assert "${CLAUDE_PLUGIN_DATA}/config.json" not in text
    assert "${CLAUDE_PLUGIN_DATA}" not in text


@pytest.mark.parametrize("name", sorted(EXPECTED_MODEL))
def test_bash_personas_forbid_redirects(name: str) -> None:
    # F3a: the jail refuses redirects for workers; the Bash tool returns stderr.
    path = AGENTS / f"{name}.md"
    if "Bash" in _list(frontmatter(path)["tools"], path):
        assert "No shell redirects" in path.read_text(), name


@pytest.mark.parametrize("name", sorted(EXPECTED_MODEL))
def test_every_persona_forbids_dashes(name: str) -> None:
    # Dash ruling: replies land in audit logs and summaries.
    text = (AGENTS / f"{name}.md").read_text()
    assert (
        "Never write U+2013 or U+2014 (en or em dash) in a reply, a file, or a ledger entry" in text
    )
    assert "U+2014" in text


@pytest.mark.parametrize("name", ["repo-coder", "charter-docs", "pr-train-conductor"])
def test_committing_personas_forbid_attribution_trailers(name: str) -> None:
    text = (AGENTS / f"{name}.md").read_text()
    assert "Commit messages carry no Co-Authored-By or other attribution trailer." in text


def test_contract_spec_writes_only_when_asked_to_save() -> None:
    text = (AGENTS / "contract-spec.md").read_text()
    assert "only when the task asks to save the packet" in text
    assert "A packet-only task ends with the" in text


def test_charter_docs_probe_status_and_dash_rule() -> None:
    text = (AGENTS / "charter-docs.md").read_text()
    contract = text.split("## Status contract", 1)[1]
    assert "- `[STATUS: LEDGER_PROBED] <probe line>`" in contract
    assert "A probe-only task ends with `[STATUS: LEDGER_PROBED] <probe line>`" in text
    assert "never claims an append" in text
    assert "Never write U+2013 or U+2014 (en or em dash)" in text
    # O7: the brief carries the absolute script path; the body never runs the variable form.
    assert "The brief names the absolute path of append_ledger.py" in text
    assert "`python3 <that path> --probe`" in text
    assert "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/append_ledger.py" not in text


@pytest.mark.parametrize("name,sub", [("nist-specialist", "nist"), ("cis-specialist", "cis")])
def test_specialists_anchor_the_manifest_to_the_cache_dir(name: str, sub: str) -> None:
    # F6: one absolute anchor; no relative manifest path, no $ or { in the body.
    text = (AGENTS / f"{name}.md").read_text()
    assert "`<cache dir>` is the absolute frameworks cache directory named in your prompt" in text
    assert f"Read `<cache dir>/{sub}/manifest.json`" in text
    assert f"Read `{sub}/manifest.json`" not in text
    # 0024: the plugin root variable is substituted at load; nothing else may carry $ or {.
    body = text.split("---\n", 2)[2].replace("${CLAUDE_PLUGIN_ROOT}/references/", "")
    assert "$" not in body and "{" not in body


JUDGES = ("nist-specialist", "cis-specialist")
JUDGE_REFERENCES = {
    "nist-specialist": "references/nist-800-53-distilled.md",
    "cis-specialist": "references/hardening-rubric.md",
}
JUDGE_CONTRACT = (
    "Your reply ends with exactly one of these, nothing after it.\n"
    "- `[STATUS: CACHE_INVALID] <detail>`\n"
    "- `[STATUS: COMPLIANCE] <PASS/FAIL list with control ids and file:line>`\n"
)


@pytest.mark.parametrize("name", JUDGES)
def test_judges_name_their_reference_files(name: str) -> None:
    # 0024: the judge's method maps the diff to an existing own-words reference file.
    text = (AGENTS / f"{name}.md").read_text()
    named = re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/(references/[A-Za-z0-9.-]+\.md)", text)
    assert JUDGE_REFERENCES[name] in named
    assert [ref for ref in named if not (REPO_ROOT / ref).is_file()] == []
    method = text.split("\n## Method\n", 1)[1].split("\n## ", 1)[0]
    assert "PASS, FAIL or N/A" in method
    rubric = text.split("\n## Rubric\n", 1)[1].split("\n## ", 1)[0]
    assert "never PASS on absence of evidence" in rubric


@pytest.mark.parametrize("name", JUDGES)
def test_judges_read_the_list_manifest(name: str) -> None:
    # 0026: the manifest is a list of entries; each file is hashed and its age noted.
    text = (AGENTS / f"{name}.md").read_text()
    phase0 = text.split("## Phase 0", 1)[1].split("\n## ", 1)[0]
    for key in ("`file`", "`sha256`", "`pinned_on`"):
        assert key in phase0, key
    assert "JSON list" in phase0
    assert "sha256sum" in phase0
    assert "90 days" in phase0
    assert "catalog_sha256" not in text


@pytest.mark.parametrize("name", JUDGES)
def test_judges_keep_their_status_contract(name: str) -> None:
    text = (AGENTS / f"{name}.md").read_text()
    assert text.split("## Status contract\n", 1)[1] == JUDGE_CONTRACT


def test_conductor_lists_the_git_reads_the_jail_allows() -> None:
    # N9: matches TestLiveRunGrammar in tests/test_checks_git_grammar.py.
    text = (AGENTS / "pr-train-conductor.md").read_text()
    for read in ("`git status`", "`git log`", "`git diff`", "`git branch`"):
        assert read in text, read
    assert "`git rev-parse --abbrev-ref HEAD`" in text
    assert "refuses `git remote`, `git branch -vv`, and `@{u}`" in text


NIST_DISTILLED = REPO_ROOT / "references" / "nist-800-53-distilled.md"
NIST_IDS = REPO_ROOT / "tests" / "fixtures" / "nist-control-ids.txt"


def test_nist_distillation_ids_exist_in_the_catalog() -> None:
    # 0024: every distilled row names a base control of the pinned catalog (oscal-content v1.5.0).
    catalog = set(NIST_IDS.read_text().split())
    rows = re.findall(r"^\| ([A-Z]{2}-[0-9]+) \|", NIST_DISTILLED.read_text(), re.MULTILINE)
    assert rows
    assert len(rows) == len(set(rows))
    assert [row for row in rows if row not in catalog] == []


RUBRIC = REPO_ROOT / "references" / "hardening-rubric.md"
RUBRIC_ITEM = re.compile(r"^- HR-[0-9]+: .+ CIS: (unmapped|[A-Za-z0-9 .]+ [0-9]+(\.[0-9]+)*)$")


def test_rubric_items_have_ids_and_cis_cites() -> None:
    # 0024: own-words items cite a CIS section number or unmapped, never CIS text.
    items = [line for line in RUBRIC.read_text().splitlines() if line.startswith("- ")]
    assert items
    assert [line for line in items if not RUBRIC_ITEM.match(line)] == []
    ids = [line.split(":", 1)[0] for line in items]
    assert len(ids) == len(set(ids))


def test_rubric_has_no_long_quotes() -> None:
    # 0024: a tripwire for pasted benchmark text, not a license proof.
    spans = re.findall('"([^"]*)"|\u201c([^\u201d]*)\u201d', RUBRIC.read_text())
    assert [s for pair in spans for s in pair if len(s) > 40] == []


AUDITOR = AGENTS / "security-auditor.md"
AUDITOR_CLASSES = (
    "secrets",
    "auth weakening",
    "broad IAM",
    "sensitive logging",
    "unsafe deserialization",
    "injection",
    "dependency manifests",
)


def test_auditor_has_a_procedure_and_severity_scale() -> None:
    # 0024: the auditor is a judge, so it carries method and rubric.
    text = AUDITOR.read_text()
    for heading in ("## Procedure", "## Severity", "## Finding format"):
        assert f"\n{heading}\n" in text, heading
    procedure = text.split("## Procedure", 1)[1].split("\n## ", 1)[0]
    for cls in AUDITOR_CLASSES:
        assert f"- {cls}: " in procedure, cls
    severity = text.split("## Severity", 1)[1].split("\n## ", 1)[0]
    for level in ("critical", "high", "medium", "low"):
        assert f"- {level}: " in severity, level
    assert "Any critical or high finding is REJECTED." in severity
    assert "`<branch> <file>:<line> <severity> <class>: <precise fix>`" in text


def test_auditor_grep_commands_pass_the_jail(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0024, 0044: every fixed pattern the procedure names must survive the auditor's hooks.
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: Config())
    commands = re.findall(r"`(git log -p -G '[^']+' <diff base>\.\.<branch>)`", AUDITOR.read_text())
    assert len(commands) == len(AUDITOR_CLASSES) - 1
    for command in commands:
        concrete = command.replace("<diff base>", "daedalus/t1").replace("<branch>", "unit-a")
        payload: dict[str, object] = {
            "agent_type": "security-auditor",
            "tool_name": "Bash",
            "tool_input": {"command": concrete},
            "cwd": "/work/repo",
        }
        assert router.route(payload, REPO_ROOT) == (True, None, ""), command


def test_auditor_verdict_first_line_contract_unchanged() -> None:
    contract = AUDITOR.read_text().split("## Status contract\n", 1)[1]
    assert contract == (
        "Your reply starts with exactly one of these verdict lines as its first line and ends with"
        " the\nsame verdict line, alone, as its last line. This holds for every reply, fix rounds"
        " included.\n"
        "- `[VERDICT: APPROVED]` then `<paragraph>` then `[VERDICT: APPROVED]`\n"
        "- `[VERDICT: REJECTED]` then `<itemized findings>` then `[VERDICT: REJECTED]`\n"
    )


@pytest.mark.parametrize("name", sorted(EXPECTED_MODEL))
def test_every_agent_carries_the_human_text_rule(name: str) -> None:
    # 0031: verbatim in every agent file; the status contract stays the last section.
    from tests.test_skills import HUMAN_TEXT_RULE

    text = (AGENTS / f"{name}.md").read_text()
    assert HUMAN_TEXT_RULE in text
    assert text.index(HUMAN_TEXT_RULE) < text.index("## Status contract")
