# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0129, 0137: the manifest priorities block, its doctor line, choice fields, packet and summary.
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from lib import train_runner, train_state
from lib.manifest import (
    DRIVERS,
    REASONS,
    Principle,
    Priorities,
    PrioritiesError,
    Rule,
)
from lib.manifest import load as load_manifest
from lib.project_keys import KEY_ROWS, MANIFEST_FILE, manifest_keys, starter_manifest
from lib.train_summary import SessionLog, parse_notes, render
from lib.workspace import mark_train

from tests.conftest import REPO_ROOT
from tests.test_train_state_print import NOTES, STATE, TRAIN, _section

AGENTS = REPO_ROOT / "agents"
BLOCK: dict[str, Any] = {
    "drivers": ["security", "trust", "ops", "cost"],
    "rules": [
        {
            "when": {"conflict": ["security", "cost"], "reason": ["certification", "framework"]},
            "then": "security",
            "note": "a control a certification asks for wins over its running cost",
        },
        {
            "when": {"conflict": ["security", "cost"], "reason": ["shape", "ownership"]},
            "then": "surface",
            "note": "separation for its own sake is the operator's call when it costs money",
        },
    ],
    "principles": [
        {
            "id": "P1",
            "driver": "security",
            "text": "Each tenant keeps its own key.",
            "source": "docs/d.md",
        }
    ],
    "agents": {"repo-coder": {"drivers": ["cost", "security", "ops", "trust"]}},
}


def _write(repo: Path, block: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps({"priorities": block}), "utf-8")


def _edited(path: str, value: object) -> dict[str, Any]:
    block = copy.deepcopy(BLOCK)
    target: Any = block
    *head, last = path.split("/")
    for part in head:
        target = target[int(part)] if part.isdigit() else target[part]
    if value is _DROP:
        del target[int(last) if last.isdigit() else last]
    else:
        target[int(last) if last.isdigit() else last] = value
    return block


_DROP = object()


# Requirement 1: the reader.


def test_reader_reads_the_f2_example(tmp_path: Path) -> None:
    _write(tmp_path, BLOCK)
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.priorities == Priorities(
        ("security", "trust", "ops", "cost"),
        (
            Rule(
                ("security", "cost"),
                ("certification", "framework"),
                "security",
                BLOCK["rules"][0]["note"],
            ),
            Rule(
                ("security", "cost"), ("shape", "ownership"), "surface", BLOCK["rules"][1]["note"]
            ),
        ),
        (Principle("P1", "security", "Each tenant keeps its own key.", "docs/d.md"),),
        (("repo-coder", ("cost", "security", "ops", "trust")),),
    )
    assert loaded.priorities.ranking("repo-coder")[0] == "cost"
    assert loaded.priorities.ranking("planner") == DRIVERS


def test_absent_block_is_none_declared(tmp_path: Path) -> None:
    (tmp_path / "service-manifest.json").write_text("{}", encoding="utf-8")
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.priorities is None


@pytest.mark.parametrize(
    ("block", "row", "needle"),
    [
        ("security", "", "must be an object"),
        ({"rules": []}, "", "lacks drivers"),
        ({**BLOCK, "weights": {}}, "", "unknown keys"),
        (
            _edited("drivers", ["security", "security", "ops", "cost"]),
            "drivers",
            "repeats the driver",
        ),
        (_edited("drivers", ["security", "trust", "ops"]), "drivers", "each of"),
        (_edited("drivers", ["security", "trust", "ops", "speed"]), "drivers", "each of"),
        (
            _edited("rules/0/when/reason", ["certifcation"]),
            "rules[].when.reason",
            "outside the reason",
        ),
        (_edited("rules/0/when/reason", []), "rules[].when.reason", "one or more"),
        (
            _edited("rules/0/when/conflict", ["security", "security"]),
            "rules[].when.conflict",
            "two distinct",
        ),
        (_edited("rules/0/then", "always"), "rules[].then", "or 'surface'"),
        (_edited("rules/0/note", ""), "rules[].note", "1 to 200"),
        (_edited("rules/0/note", "x" * 201), "rules[].note", "1 to 200"),
        (_edited("rules/0/note", _DROP), "rules[].then", "lacks note"),
        (_edited("rules", [BLOCK["rules"][0]] * 33), "rules[].then", "at most 32"),
        (_edited("principles/0/id", "p1"), "principles[].id", "P followed by digits"),
        (_edited("principles", [BLOCK["principles"][0]] * 2), "principles[].id", "unique"),
        (_edited("principles/0/driver", "speed"), "principles[].driver", "a driver"),
        (_edited("principles/0/text", "x" * 301), "principles[].text", "1 to 300"),
        (_edited("principles/0/source", "/etc/x"), "principles[].source", "repo-relative"),
        (
            _edited("agents", {"security-auditor": {"drivers": DRIVERS}}),
            "agents.<name>.drivers",
            "no project overrides",
        ),
        (
            _edited("agents", {"ghost": {"drivers": list(DRIVERS)}}),
            "agents.<name>.drivers",
            "not a Daedalus agent",
        ),
        (_edited("agents/repo-coder/drivers", ["cost"]), "agents.<name>.drivers", "each of"),
    ],
)
def test_reader_refuses_each_malformed_block(
    tmp_path: Path, block: object, row: str, needle: str
) -> None:
    _write(tmp_path, block)
    with pytest.raises(PrioritiesError) as caught:
        load_manifest(tmp_path)
    message = str(caught.value)
    assert caught.value.row == row and needle in message, message
    assert message.count("Next:") == 1 and "(0129)" in message


def test_every_reason_word_is_accepted(tmp_path: Path) -> None:
    _write(tmp_path, _edited("rules/0/when/reason", list(REASONS)))
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.priorities is not None
    assert loaded.priorities.rules[0].reason == REASONS


# Requirement 2: key reference rows and the starter manifest.


def test_one_key_reference_row_per_field_and_no_starter_key() -> None:
    keys = [k for k in manifest_keys() if k.startswith("priorities.")]
    assert keys == [
        "priorities.drivers",
        "priorities.rules[].when.conflict",
        "priorities.rules[].when.reason",
        "priorities.rules[].then",
        "priorities.rules[].note",
        "priorities.principles[].id",
        "priorities.principles[].driver",
        "priorities.principles[].text",
        "priorities.principles[].source",
        "priorities.agents.<name>.drivers",
    ]
    assert all((MANIFEST_FILE, key) in KEY_ROWS for key in keys)
    assert manifest_keys().index("priorities.drivers") == manifest_keys().index("docs.literacy") + 1
    assert "priorities" not in starter_manifest()


# Requirement 3: the doctor line.


def _doctor_lines(repo: Path) -> list[str]:
    import daedalus_doctor

    return [line for _, line in daedalus_doctor._priorities_check(repo)]


def test_doctor_prints_the_ranking_and_rule_count(tmp_path: Path) -> None:
    _write(tmp_path, BLOCK)
    assert _doctor_lines(tmp_path) == ["OK   priorities: security > trust > ops > cost, 2 rules"]
    (tmp_path / "service-manifest.json").write_text("{}", encoding="utf-8")
    assert _doctor_lines(tmp_path) == ["OK   priorities: none declared"]


def test_doctor_names_the_row_a_malformed_block_broke(tmp_path: Path) -> None:
    _write(tmp_path, _edited("rules/1/when/reason", ["speed"]))
    [line] = _doctor_lines(tmp_path)
    assert line.startswith("MISS priorities: the block breaks key reference row ")
    assert "priorities.rules[].when.reason" in line and "Next:" in line


# Requirement 4: choice fields.


@pytest.fixture
def train(repo_cwd: Path, project_data: Path) -> Path:
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    return repo_cwd


def _choices(repo: Path) -> list[dict[str, object]]:
    state = train_state.load(repo, TRAIN)
    return [dict(c) for c in state.get(train_state.CHOICES, [])]  # type: ignore[union-attr]


def test_a_matching_rule_writes_one_choice_record_and_no_brief(train: Path) -> None:
    out = train_runner.choice(
        train,
        "one key per tenant",
        "one shared key",
        "a key per tenant",
        driver="security",
        rule="1",
    )
    assert out.code == 0
    assert out.lines == [
        "Chose one key per tenant over one shared key: a key per tenant (driver security, rule 1)"
    ]
    assert _choices(train) == [
        {
            "chose": "one key per tenant",
            "over": "one shared key",
            "cost": "a key per tenant",
            "driver": "security",
            "rule": "1",
        }
    ]
    assert not (train / "docs" / ".tmp" / "daedalus" / TRAIN / "decisions").exists()


@pytest.mark.parametrize("field", ["driver", "rule"])
@pytest.mark.parametrize("value", ["", "x" * 201, "two\nlines"])
def test_choice_fields_keep_the_one_line_rule(train: Path, field: str, value: str) -> None:
    out = train_runner.choice(train, "a", "b", "c", **{field: value})
    assert out.code != 0 and f"--{field} must be one printable line of 1 to 200" in out.lines[0]
    assert _choices(train) == []


def test_choice_cli_takes_driver_and_rule(train: Path) -> None:
    import subprocess
    import sys

    from tests.conftest import SCRIPTS_DIR

    argv = [sys.executable, str(SCRIPTS_DIR / "daedalus_train.py"), "choice", "--repo", str(train)]
    argv += ["--chose", "a", "--over", "b", "--cost", "c", "--driver", "cost", "--rule", "P1"]
    done = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=train)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "Chose a over b: c (driver cost, rule P1)"


# Requirements 5 to 7: the packet section and the agents' rules.


def _flat(name: str) -> str:
    return " ".join((AGENTS / f"{name}.md").read_text(encoding="utf-8").split())


def test_specialist_writes_the_pinned_priorities_section() -> None:
    text = _flat("standards-rules-specialist")
    for line in (
        "`## Priorities`",
        "`ranking: <driver> > <driver> > <driver> > <driver>`",
        "`rule <n>: <driver> vs <driver> for <reason>[,<reason>...] "
        "then <driver or surface>: <note>`",
        "`principle <id> (<driver>): <text>`",
        "`priorities: none declared`",
        "in every train kind",
    ):
        assert line in text, line


def test_orchestrator_walks_the_rules_and_a_surface_brief_quotes_the_note() -> None:
    text = _flat("orchestrator")
    rule = text[text.index("- Priorities (0129, 0137)") : text.index("- Progress (0085)")]
    for phrase in (
        "walk the `rule <n>` lines in order; the first match decides",
        "decide alone, write no decision brief, and run the choice command with "
        "`--driver <driver> --rule <n>` added",
        "`recommended by <driver> over <driver>; rule <n>: <note>`, quoting the rule's note",
        "`--driver <driver> --rule ranking`",
        "`Priorities: the ## Priorities section of <standards packet path>`",
        "never the operator's own session",
    ):
        assert phrase in rule, phrase


def test_coder_yields_a_surfaced_default_and_the_auditor_keeps_its_severity() -> None:
    coder = _flat("repo-coder")
    assert "`[STATUS: YIELD_STANDARDS] priorities rule <n>: <the default and its options>`" in coder
    assert "the `agent repo-coder:` line when present, else the `ranking:` line" in coder
    auditor = _flat("security-auditor")
    assert "No rule, principle or ranking lowers a finding's severity or waives it" in auditor


# Requirement 8: the summary section.


def test_summary_lists_settled_and_surfaced_decisions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, BLOCK)
    state = {
        **STATE,
        "choices": [
            {"chose": "warm resume", "over": "cold dispatch", "cost": "40k tokens"},
            {
                "chose": "a key per tenant",
                "over": "one key",
                "cost": "c",
                "driver": "security",
                "rule": "1",
            },
            {
                "chose": "split the domain",
                "over": "one domain",
                "cost": "c",
                "driver": "security",
                "rule": "2",
            },
        ],
    }
    command = (
        f"python3 /p/scripts/daedalus_train.py choice --repo {repo} --chose 'a key per tenant' "
        "--over 'one key' --cost c --driver security --rule 1"
    )
    records = [
        {
            "seq": 1,
            "event": "PreToolUse",
            "tool_name": "Bash",
            "agent_type": "daedalus:orchestrator",
            "tool_input": {"command": command},
            "decision": "allow",
        }
    ]
    log = SessionLog("sess-a", tmp_path / "sess-a.jsonl", records)
    text = render(repo, TRAIN, state, [log], parse_notes(NOTES, "notes"), False, None)
    assert _section(text, "Priorities") == [
        "- settled alone by rule 1, driver security, orchestrator: a key per tenant over one key",
        "- surfaced by rule 2, driver security, unknown agent: split the domain over one domain",
    ]
    assert text.index("\n## Priorities\n") > text.index("\n## Rulings\n")
    assert text.index("\n## Priorities\n") < text.index("\n## Units\n")
