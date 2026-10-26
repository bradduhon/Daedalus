# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0133, 0139, 0142: every failing gate goes to the operator finding by finding, no round budget.
from __future__ import annotations

import copy
import json
import re
from dataclasses import fields
from pathlib import Path

import pytest
from lib import audit_rounds, gh_policy, train_runner, train_state
from lib.audit_proof import ProofError, findings_path, push_proof
from lib.config import Config, ConfigError, load_config
from lib.project_keys import CONFIG_FILE, KEY_ROWS, config_keys

from tests import test_train_runner as runner_tests
from tests.conftest import REPO_ROOT
from tests.test_train_runner import (
    A,
    B,
    C,
    _agent_stop,
    _audit_train,
    _commit_on_integration,
    _findings,
    _rejected_round,
    _state,
    _verdict,
    _verdict_call,
)
from tests.test_train_state_print import STATE, TIP, _section, _text

# 0133: the runner tests' fixtures, a temp HOME, a plugin root and a one-commit repository.
_isolated_env = runner_tests._isolated_env
plugin = runner_tests.plugin
repo = runner_tests.repo

KEY_A, KEY_B, KEY_C = (line.split(" | ", 1)[0] for line in (A, B, C))
HIGH = "audit/round3/test_new.py::test_refused | high | scope"
ID, ID2 = "0143-DAE-PLT", "0144-DAE-PLT"
GATE_KEY = "audit/round1/test_gate.py::test_refused"
CHOICES = ("`Fix it now (Recommended)`", "`Skip, track or exempt it`", "`Stop the train`")
TRACKING = (
    "`Skip it`",
    "`Track it`",
    "`Exempt it`",
    "Other: the operator's own words",
)
PROMPT_START = (
    "Put it to the operator with AskUserQuestion, in the decision-brief shape (0103), one "
    "question per finding:"
)
PROMPT_END = (
    "Never start a fix round without a `Fix it now` pick, and never stop the train on your "
    "own authority."
)
RETIRED_WORDS = ("budget_left", "escalate reason=", "continue round=", "stall")


def exempt_round(repo: Path, train: str, tip: str, tracking: str = "issue") -> None:
    # 0133: a rejected round 1 with one finding, its findings file and its exemption.
    path = findings_path(repo, train, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{GATE_KEY} | high | scope\n", encoding="utf-8")
    entry = {"ledger_id": "0104-DAE-PLT", "tip": tip, "tracking": tracking}
    train_state.update(
        repo,
        train,
        verdict={"status": "rejected", "tip": tip, "round": 1, "seq": 9},
        audit_rounds={"1": {GATE_KEY: {"severity": "high", "class": "scope"}}},
        exemptions={"1": {GATE_KEY: entry}},
    )


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _prompt(text: str) -> str:
    flat = " ".join(text.split())
    assert flat.count(PROMPT_START) == 1, "one per-finding prompt"
    return flat.split(PROMPT_START, 1)[1].split(PROMPT_END, 1)[0]


def _step4() -> str:
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    return recipe.split("## Phase 3", 1)[1].split("\n4. ", 1)[1].split("\n5. ", 1)[0]


# Requirements 1 and 2: the verdict command records the round and prints no stall word.


def test_rejected_verdict_prints_one_record_line_with_no_budget(repo: Path, plugin: Path) -> None:
    # 0133: a recurring set, a new high and more rounds than the old budget all just record.
    tip = _audit_train(repo, plugin)
    rounds = [(A, B), (A, B), (HIGH,), (A,), (A,), (A,), (A,)]
    for number, lines in enumerate(rounds, start=1):
        outcome = _rejected_round(repo, tip, number, *lines)
        assert outcome.code == 0, outcome.lines
        assert outcome.lines == [f"recorded rejected round={number} findings={len(lines)}"]
        assert not any(word in outcome.lines[0] for word in RETIRED_WORDS)
    recorded = _state(repo)["audit_rounds"]
    assert isinstance(recorded, dict) and sorted(recorded, key=int) == [str(n) for n in range(1, 8)]
    assert recorded["3"] == {HIGH.split(" | ")[0]: {"severity": "high", "class": "scope"}}
    assert _state(repo)["verdict"]["round"] == 7  # type: ignore[index]


def test_the_stall_rule_and_its_budget_are_gone() -> None:
    for name in ("judge", "HIGH"):
        assert not hasattr(audit_rounds, name), name
    assert audit_rounds.next_round({"1": {}, "2": {}}) == 3


# Requirement 3: the config key is retired and refused with a Next line naming its removal.


@pytest.mark.parametrize("value", [5, 1, None, "3"])
def test_a_config_that_sets_the_round_budget_is_refused(tmp_path: Path, value: object) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"audit_round_budget": value}), encoding="utf-8")
    with pytest.raises(ConfigError) as info:
        load_config(path=path)
    text = str(info.value)
    assert "sets audit_round_budget, which Daedalus removed" in text
    assert "Next: delete the audit_round_budget line from .claude/daedalus/config.json." in text
    path.write_text(json.dumps({"max_concurrent_builders": 2}), encoding="utf-8")
    assert load_config(path=path).max_concurrent_builders == 2


def test_the_round_budget_is_no_config_field_or_key_row() -> None:
    assert "audit_round_budget" not in {item.name for item in fields(Config)}
    assert "audit_round_budget" not in config_keys()
    assert (CONFIG_FILE, "audit_round_budget") not in KEY_ROWS


# Requirements 4 and 13: one exemption per finding, with its tracking choice beside it.


def test_exception_records_one_exemption_per_finding(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    none = train_runner.record_exception(repo, ID, KEY_A, "issue")
    assert none.code == 1 and "records no rejected verdict" in none.lines[0]
    assert "Next:" in none.lines[0]
    assert _rejected_round(repo, tip, 1, A, B).code == 0
    first = train_runner.record_exception(repo, ID, KEY_A, "issue")
    assert first.code == 0, first.lines
    assert first.lines == [
        f"exemption recorded finding={KEY_A} round=1 ledger={ID} tracking=issue remaining=1"
    ]
    second = train_runner.record_exception(repo, ID2, KEY_B, "other", " the release checklist ")
    assert second.lines[0].endswith("tracking=other remaining=0")
    assert _state(repo)["exemptions"] == {
        "1": {
            KEY_A: {"ledger_id": ID, "tip": tip, "tracking": "issue"},
            KEY_B: {
                "ledger_id": ID2,
                "tip": tip,
                "tracking": "other",
                "other": "the release checklist",
            },
        }
    }
    # 0133: the verdict record stays as recorded beside the exemptions.
    assert _state(repo)["verdict"]["status"] == "rejected"  # type: ignore[index]
    again = train_runner.record_exception(repo, ID, KEY_A, "local")
    assert again.code == 1 and "already carries an exemption" in again.lines[0]


@pytest.mark.parametrize(
    ("ledger", "finding", "tracking", "other", "why"),
    [
        ("--force", KEY_A, "issue", None, "is not a ledger id"),
        (ID, "", "issue", None, "--finding must name one finding id"),
        (ID, "not/a/finding", "issue", None, "is not in the rejected round 1"),
        (ID, KEY_A, "tracked", None, "is not one of dropped, issue, local, other"),
        (ID, KEY_A, "other", None, "--other carries the operator's own words"),
        (ID, KEY_A, "issue", "words", "--other carries the operator's own words"),
        (ID, KEY_A, "other", "two\nlines", "--other must be one printable line"),
    ],
)
def test_exception_refuses_off_shape_input_with_a_next_line(
    repo: Path,
    plugin: Path,
    ledger: str,
    finding: str,
    tracking: str,
    other: str | None,
    why: str,
) -> None:
    tip = _audit_train(repo, plugin)
    _rejected_round(repo, tip, 1, A)
    refused = train_runner.record_exception(repo, ledger, finding, tracking, other)
    assert refused.code == 1 and why in refused.lines[0] and "Next:" in refused.lines[0]
    assert "exemptions" not in _state(repo)


def test_every_tracking_choice_is_accepted(repo: Path, plugin: Path) -> None:
    # 0142: no environment routes a choice away; each value records.
    tip = _audit_train(repo, plugin)
    _rejected_round(repo, tip, 1, A, B, C, HIGH)
    keys = [KEY_A, KEY_B, KEY_C, HIGH.split(" | ")[0]]
    for key, tracking in zip(keys, train_state.TRACKING, strict=True):
        other = "kept in the team notes" if tracking == "other" else None
        assert train_runner.record_exception(repo, ID, key, tracking, other).code == 0
    exempt = train_state.record(train_state.record(_state(repo), "exemptions"), "1")
    assert sorted(str(v["tracking"]) for v in exempt.values()) == sorted(train_state.TRACKING)  # type: ignore[index]


def test_exception_refuses_when_the_tip_moved(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    _rejected_round(repo, tip, 1, A)
    _commit_on_integration(repo)
    refused = train_runner.record_exception(repo, ID, KEY_A, "issue")
    assert refused.code == 1 and "moved past the judged tip" in refused.lines[0]


def test_exception_command_line_takes_finding_and_tracking() -> None:
    import daedalus_train

    parser = daedalus_train._parser()
    args = parser.parse_args(
        ["exception", "--repo", "/r", "--ledger-id", ID, "--finding", KEY_A, "--tracking", "local"]
    )
    assert (args.ledger_id, args.finding, args.tracking, args.other) == (ID, KEY_A, "local", None)
    for missing in ("--finding", "--tracking"):
        argv = ["exception", "--repo", "/r", "--ledger-id", ID, "--finding", KEY_A]
        argv += ["--tracking", "issue"]
        index = argv.index(missing)
        with pytest.raises(SystemExit):
            parser.parse_args(argv[:index] + argv[index + 2 :])


# Requirement 5: the push proof, the gh gate and the CLI read one exemption per finding.


def test_push_proof_passes_only_when_every_finding_is_exempted(
    repo: Path, plugin: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import verify_audit_chain

    tip = _audit_train(repo, plugin)
    train = str(_state(repo)["train_id"])
    _rejected_round(repo, tip, 1, A, B)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"finding {KEY_A} of the rejected round 1 has no exemption, 2 of 2" in str(info.value)
    assert "Next:" in str(info.value)
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is not None
    train_runner.record_exception(repo, ID, KEY_A, "issue")
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"finding {KEY_B} of the rejected round 1 has no exemption, 1 of 2" in str(info.value)
    train_runner.record_exception(repo, ID, KEY_B, "dropped")
    ok = f"OK approved: every finding exempted, train {train}, round 1, integration tip {tip[:12]}"
    assert push_proof(repo, train) == ok
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is None
    assert verify_audit_chain.main(["v", "--approved", train, "--repo", str(repo)]) == 0
    assert capsys.readouterr().out == f"{ok}\n"
    # 0133: a finding the file gains after the verdict counts too.
    _findings(repo, 1, A, B, C)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"finding {KEY_C} of the rejected round 1 has no exemption" in str(info.value)
    _findings(repo, 1, A, B)
    assert push_proof(repo, train) == ok
    moved = _commit_on_integration(repo)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"the tip {moved[:12]} moved past the judged tip {tip[:12]}" in str(info.value)
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is not None


def test_an_earlier_rounds_exemption_never_covers_a_later_round(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    train = str(_state(repo)["train_id"])
    _rejected_round(repo, tip, 1, A)
    train_runner.record_exception(repo, ID, KEY_A, "issue")
    assert push_proof(repo, train).startswith("OK approved: every finding exempted")
    _rejected_round(repo, tip, 2, A)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"finding {KEY_A} of the rejected round 2 has no exemption" in str(info.value)


@pytest.mark.parametrize(
    "broken",
    [
        {"ledger_id": "", "tip": None, "tracking": "issue"},
        {"ledger_id": ID, "tip": "c" * 40, "tracking": "issue"},
        {"ledger_id": ID, "tip": None, "tracking": "unknown"},
        "not an object",
    ],
)
def test_a_malformed_exemption_never_passes(repo: Path, plugin: Path, broken: object) -> None:
    tip = _audit_train(repo, plugin)
    train = str(_state(repo)["train_id"])
    _rejected_round(repo, tip, 1, A)
    entry = {**broken, "tip": broken["tip"] or tip} if isinstance(broken, dict) else broken
    train_state.update(repo, train, exemptions={"1": {KEY_A: entry}})
    with pytest.raises(ProofError):
        push_proof(repo, train)
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is not None


def test_an_approved_verdict_still_takes_its_own_path(repo: Path, plugin: Path) -> None:
    # 0133: the rejected path never admits an approved state; a rejection lacking a file refuses.
    tip = _audit_train(repo, plugin)
    train = str(_state(repo)["train_id"])
    _rejected_round(repo, tip, 1, A)
    train_runner.record_exception(repo, ID, KEY_A, "issue")
    findings_path(repo, train, 1).unlink()
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert "the rejected round 1 finding list is unreadable" in str(info.value)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    assert _verdict_call(repo, "approved", None, tip=tip).code == 0
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert "every finding exempted" not in str(info.value)


# Requirements 6, 7 and 12: the per-finding question and the tracking question.


def test_the_orchestrator_puts_each_finding_to_the_operator() -> None:
    step = _step4()
    flat = " ".join(step.split())
    assert "It prints `recorded rejected round=<n> findings=<k>`" in flat
    for word in RETIRED_WORDS:
        assert word not in flat, word
    assert "every finding in the round's findings file goes to the operator as one decision" in flat
    assert "plus the tracking question on an exemption" in flat
    prompt = _prompt(step)
    places = [prompt.index(choice) for choice in CHOICES]
    assert places == sorted(places)
    tracking = prompt.split("- Tracking question", 1)[1]
    assert (
        "a second prompt asked only after `Skip, track or exempt it`, never a fourth choice"
        in tracking
    )
    assert "Every choice is offered in every environment" in tracking
    for choice in TRACKING:
        assert choice in tracking, choice
    head = prompt.split("- Tracking question", 1)[0]
    assert not any(choice in head for choice in TRACKING[:3])
    assert PROMPT_END in flat
    assert flat.index(PROMPT_END) < flat.index("SendMessage(each responsible coder")
    assert "`[STATUS: EXCEPTION] ledger_id=<the exception ruling's id>`" in flat
    assert "`Exempt: <finding id> tracking=<dropped, issue, local or other>`" in flat
    assert "daedalus_train.py exception" not in (
        REPO_ROOT / "agents" / "orchestrator.md"
    ).read_text(encoding="utf-8")


def test_the_recovery_round_uses_the_per_finding_step() -> None:
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    recovery = " ".join(recipe.split("## Recovery", 1)[1].split("## Status contract", 1)[0].split())
    assert (
        "Run the step 4 per-finding step with these findings, one question per finding" in recovery
    )
    assert "escalation" not in recovery


def test_the_orchestrator_frontmatter_and_status_contract_are_unchanged() -> None:
    # Requirement 9: the generated agent tables read these lines, so they stay as they were.
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    head = recipe.split("\n---\n", 1)[0]
    assert (
        "description: Runs one Build Train from its plan to the audited integration tip. Starts "
        "coders and specialists, routes their yields, keeps the State Block and judges every "
        "return; hands each operator decision to the main session, never pushes and never "
        "merges into main."
    ) in head
    assert "model: fable" in head and "shape: dispatcher" in head
    contract = recipe.split("## Status contract\n", 1)[1].splitlines()
    assert contract[1:5] == [
        "- `[STATUS: DECISION] brief=<path> questions=<n>`",
        "- `[STATUS: EXCEPTION] ledger_id=<id>`",
        "- `[STATUS: TRAIN_COMPLETE] summary=<path> audit_log=<path> tip=<40 hex>`",
        "- `[STATUS: STOP] reason=<what happened> next=<next action>`",
    ]


def test_the_prompt_uses_the_operators_plain_labels() -> None:
    # Contract v2 pins 7 and 12: the three verb labels, the three tracking labels, stored values.
    catalog = (REPO_ROOT / "skills" / "catalog" / "SKILL.md").read_text(encoding="utf-8")
    for prompt in (_prompt(_step4()), _prompt(catalog)):
        head, tracking = prompt.split("- Tracking question", 1)
        choices = [
            "- `Fix it now (Recommended)`: runs a fix round.",
            "- `Skip, track or exempt it`: exempts the finding.",
            "- `Stop the train`: ends the train.",
        ]
        places = [head.index(choice) for choice in choices]
        assert places == sorted(places)
        assert "the how of a fix stays out of the option text and lives in the finding file" in head
        assert "the first line states what is at stake in one plain sentence, then asks" in head
        for label, stored in (
            ("Skip it", "dropped"),
            ("Track it", "issue"),
            ("Exempt it", "local"),
        ):
            assert f"- `{label}`:" in tracking and f"stored as `{stored}`" in tracking, label
        assert "stored as `other`" in tracking
        for old in ("Exempt the finding", "Run a fix round", "End the train", "Silently dropped"):
            assert old not in prompt, old
    assert list(train_state.TRACKING) == ["dropped", "issue", "local", "other"]
    assert list(train_state.TRACKING.values())[:3] == ["Skip it", "Track it", "Exempt it"]


def test_the_catalog_carries_the_same_per_finding_prompt() -> None:
    catalog = (REPO_ROOT / "skills" / "catalog" / "SKILL.md").read_text(encoding="utf-8")
    assert _prompt(catalog) == _prompt(_step4())
    section = " ".join(catalog.split("## The per-finding audit prompt", 1)[1].split())
    assert section.startswith("Every rejected round puts each finding in its findings file")
    assert "## The audit escalation prompt" not in catalog
    loop = " ".join(catalog.split("- Audit loop", 1)[1].split("\n", 1)[0].split())
    assert "no round budget applies" in loop and "`escalate`" not in loop
    assert "--finding <finding id> --tracking <dropped|issue|local|other> [--other" in " ".join(
        catalog.split()
    )


def test_the_relays_record_per_finding_exemptions() -> None:
    # Requirements 7 and 14: one exception call per finding, and the tracking answer's trail.
    build = _flat(REPO_ROOT / "skills" / "build-train" / "SKILL.md")
    route = build.split("- `[STATUS: EXCEPTION] ledger_id=<id>`:", 1)[1].split(" - `[STATUS:", 1)[0]
    assert (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py exception --repo <repo> "
        "--ledger-id <id> --finding <finding id> --tracking <answer>`"
    ) in route
    assert "for `Track it` (`issue`) you file the four-field tracked-risk issue" in route
    assert "for `Skip it` (`dropped`) or `Exempt it` (`local`)" in route
    assert "`Deviation:` line naming the finding and its exemption row" in route
    assert "binds the ruling to the integration tip" not in route
    push = _flat(REPO_ROOT / "skills" / "push-train" / "SKILL.md")
    step9 = push.split(" 9. ", 1)[1].split(" 10. ", 1)[0]
    assert "a rejected round on the current tip whose every finding carries the operator's" in step9
    assert "four-field tracked-risk issue is filed before the pull request opens" in step9
    assert "`Deviation:` line naming the finding and its exemption row" in step9
    assert "a merge with each finding as a tracked-risk issue" not in push


def test_the_round_budget_is_gone_from_the_prose() -> None:
    # Requirement 10: the docs and recipes name no round budget.
    for rel in (
        "README.md",
        "docs/howto/README.md",
        "docs/project-requirements.md",
        "agents/orchestrator.md",
        "skills/catalog/SKILL.md",
        "skills/build-train/SKILL.md",
        "skills/push-train/SKILL.md",
    ):
        text = _flat(REPO_ROOT / rel)
        assert "audit_round_budget" not in text, rel
        assert not re.search(r"\bround budget (runs|ran) out\b", text), rel


# Requirements 8 and 13: the summary Audit section lists each exemption with its tracking.


def test_the_summary_lists_each_exempted_finding(tmp_path: Path) -> None:
    state = copy.deepcopy(STATE)
    state["verdict"] = {"status": "rejected", "tip": TIP, "round": 2, "seq": 9}
    keys = ("a.py::t1", "b.py::t2", "c.py::t3", "d.py::t4")
    state["audit_rounds"] = {
        "1": {"a.py::t1": {"severity": "high"}},
        "2": {key: {"severity": "low"} for key in keys},
    }
    state["exemptions"] = {
        "2": {
            "a.py::t1": {"ledger_id": "0143-DAE-PLT", "tip": TIP, "tracking": "issue"},
            "b.py::t2": {"ledger_id": "0144-DAE-PLT", "tip": TIP, "tracking": "local"},
            "c.py::t3": {"ledger_id": "0145-DAE-PLT", "tip": TIP, "tracking": "dropped"},
            "d.py::t4": {
                "ledger_id": "0146-DAE-PLT",
                "tip": TIP,
                "tracking": "other",
                "other": "the release checklist",
            },
        }
    }
    audit = _section(_text(tmp_path, state), "Audit")
    assert audit[:7] == [
        f"[VERDICT: REJECTED] tip={TIP} after 2 round(s); the operator exempted 4 of the 4 "
        "finding(s) of round 2.",
        "- Exempted a.py::t1 (0143-DAE-PLT), tracking: Track it",
        "- Exempted b.py::t2 (0144-DAE-PLT), tracking: Exempt it",
        "Deviation: finding b.py::t2 exempted with no tracked issue (Exempt it), "
        "exemption row 0144-DAE-PLT.",
        "- Exempted c.py::t3 (0145-DAE-PLT), tracking: Skip it",
        "Deviation: finding c.py::t3 exempted with no tracked issue (Skip it), "
        "exemption row 0145-DAE-PLT.",
        "- Exempted d.py::t4 (0146-DAE-PLT), tracking: Other: the release checklist",
    ]
    assert audit[7:] == [
        "Round 1: rejected, 1 finding(s) (1 high)",
        "Round 2: rejected, 4 finding(s) (4 low)",
        "Docs: not run",
    ]
    del state["exemptions"]
    assert _section(_text(tmp_path, state), "Audit")[0] == (
        f"[VERDICT: REJECTED] tip={TIP} after 2 round(s)."
    )
