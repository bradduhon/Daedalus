# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0131, 0134: the docs verdict record, the two-verdict summary and the docs-only push proof rule.
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from lib import gh_policy, train_runner, train_state
from lib.audit_proof import (
    PUBLIC_DOCS,
    ProofError,
    docs_findings_path,
    push_proof,
    tip_admits,
)

from tests import test_train_runner as runner_tests
from tests.conftest import REPO_ROOT
from tests.conftest import git as _git
from tests.test_operator_gates import KEY_A
from tests.test_train_runner import (
    A,
    _agent_stop,
    _audit_train,
    _integration,
    _record,
    _rejected_round,
    _state,
)
from tests.test_train_state_print import STATE, TIP, _section, _text

# 0131: the runner tests' fixtures, a temp HOME, a plugin root and a one-commit repository.
_isolated_env = runner_tests._isolated_env
plugin = runner_tests.plugin
repo = runner_tests.repo

CLAIM, CLAIM2 = "README.md:12", "docs/howto/README.md:40"
ID = "0150-DAE-PLT"


def _train(repo: Path) -> str:
    return str(_state(repo)["train_id"])


def _commit(repo: Path, *paths: str) -> str:
    # 0131: one commit on the integration branch touching the paths given.
    for name in paths:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"{name} {target.stat().st_size if target.exists() else 0}\n")
        _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", f"change {' '.join(paths)}")
    return _integration(repo)


def _docs_unit(repo: Path) -> Path:
    # 0134: the docs worktree the documentation stage records as unit <train-id>-docstage.
    train = _train(repo)
    name = f"{train}{train_state.DOCS_SUFFIX}"
    path = repo.parent / name
    train_state.add_unit(repo, train, name, f"daedalus-unit/{name}", path)
    return path


def _verifier_says(repo: Path, worktree: Path, line: str) -> None:
    # 0121: a claims-mode dispatch naming the docs worktree, then the verifier's reply.
    prompt = f"CLAIMS MODE.\nClaim: {CLAIM} a claim\nUnit worktree: {worktree}"
    _record(repo, tool_name="Agent", tool_input={"subagent_type": "verifier", "prompt": prompt})
    _agent_stop(repo, "verifier", f"{line}\nrows\n{line}", "ver-1")


def _claims(repo: Path, *keys: str) -> Path:
    path = docs_findings_path(repo, _train(repo))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key} | medium | docs\n" for key in keys), encoding="utf-8")
    return path


def _exempted_security(repo: Path, plugin: Path) -> str:
    # 0133: a rejected round with its one finding exempted, so the proof has a judged tip.
    tip = _audit_train(repo, plugin)
    _rejected_round(repo, tip, 1, A)
    assert train_runner.record_exception(repo, ID, KEY_A, "issue").code == 0
    return tip


# Requirement 1: the docs verdict record.


def test_docs_verdict_verified_reads_the_verifier_reply(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    none = train_runner.record_docs_verdict(repo, "verified")
    assert none.code == 1 and "records no docs worktree" in none.lines[0]
    worktree = _docs_unit(repo)
    unread = train_runner.record_docs_verdict(repo, "verified")
    assert unread.code == 1 and "no verifier reply ends" in unread.lines[0]
    assert "Next:" in unread.lines[0]
    _verifier_says(repo, worktree, "[VERDICT: REFUTED] README.md:12 code")
    assert train_runner.record_docs_verdict(repo, "verified").code == 1
    _verifier_says(repo, worktree, "[VERDICT: VERIFIED] claims=1")
    outcome = train_runner.record_docs_verdict(repo, "verified")
    assert outcome.code == 0, outcome.lines
    assert outcome.lines == [f"docs verdict recorded status=verified tip={tip[:12]}"]
    assert _state(repo)["docs_verdict"] == {"status": "verified", "tip": tip}
    # 0131: the security verdict record stays apart.
    assert "verdict" not in _state(repo)


def test_docs_verdict_refuted_records_its_claim_file(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    want = docs_findings_path(repo, _train(repo))
    missing = train_runner.record_docs_verdict(repo, "refuted")
    assert missing.code == 1 and f"--findings {want}" in missing.lines[0]
    elsewhere = repo / "findings.txt"
    elsewhere.write_text(f"{CLAIM} | low | docs\n", encoding="utf-8")
    wrong = train_runner.record_docs_verdict(repo, "refuted", findings=elsewhere)
    assert wrong.code == 1 and "is not the docs claim file" in wrong.lines[0]
    empty = train_runner.record_docs_verdict(repo, "refuted", findings=_claims(repo))
    assert empty.code == 1 and "lists no claims" in empty.lines[0]
    path = _claims(repo, CLAIM, CLAIM2)
    outcome = train_runner.record_docs_verdict(repo, "refuted", findings=path)
    assert outcome.lines == [f"docs verdict recorded status=refuted tip={tip[:12]}"]
    record = _state(repo)["docs_verdict"]
    assert record == {
        "status": "refuted",
        "tip": tip,
        "findings": {
            CLAIM: {"severity": "medium", "class": "docs"},
            CLAIM2: {"severity": "medium", "class": "docs"},
        },
    }


@pytest.mark.parametrize(
    ("status", "tip", "findings", "why"),
    [
        ("approved", None, False, "is neither verified nor refuted"),
        ("verified", "b" * 40, False, "is not the integration tip"),
        ("verified", None, True, "takes --findings only when refuted"),
    ],
)
def test_docs_verdict_refuses_off_shape_calls(
    repo: Path, plugin: Path, status: str, tip: str | None, findings: bool, why: str
) -> None:
    _audit_train(repo, plugin)
    path = _claims(repo, CLAIM) if findings else None
    refused = train_runner.record_docs_verdict(repo, status, tip, path)
    assert refused.code == 1 and why in refused.lines[0] and "Next:" in refused.lines[0]
    assert "docs_verdict" not in _state(repo)


def test_the_verdict_command_line_takes_the_docs_gate() -> None:
    import daedalus_train

    args = daedalus_train._parser().parse_args(
        ["verdict", "--repo", "/r", "--gate", "docs", "--status", "verified"]
    )
    assert (args.gate, args.status, args.round_) == ("docs", "verified", None)
    plain = daedalus_train._parser().parse_args(["verdict", "--repo", "/r", "--status", "x"])
    assert plain.gate == "security"
    with pytest.raises(SystemExit):
        daedalus_train._parser().parse_args(
            ["verdict", "--repo", "/r", "--gate", "release", "--status", "verified"]
        )


def test_the_docs_gate_refuses_a_round(repo: Path, plugin: Path) -> None:
    import daedalus_train

    _audit_train(repo, plugin)
    args = daedalus_train._parser().parse_args(
        ["verdict", "--repo", str(repo), "--gate", "docs", "--status", "verified", "--round", "2"]
    )
    outcome = daedalus_train._dispatch(args)
    assert outcome.code == 1 and "takes no --round or --seq" in outcome.lines[0]


def test_a_refuted_docs_claim_takes_its_exemption_into_the_docs_record(
    repo: Path, plugin: Path
) -> None:
    tip = _exempted_security(repo, plugin)
    train_runner.record_docs_verdict(repo, "refuted", findings=_claims(repo, CLAIM, CLAIM2))
    first = train_runner.record_exception(repo, ID, CLAIM, "local")
    assert first.lines == [
        f"exemption recorded finding={CLAIM} gate=docs ledger={ID} tracking=local remaining=1"
    ]
    again = train_runner.record_exception(repo, ID, CLAIM, "issue")
    assert again.code == 1 and "already carries an exemption" in again.lines[0]
    exempt = train_state.record(_state(repo)["docs_verdict"], "exemptions")  # type: ignore[arg-type]
    assert exempt == {CLAIM: {"ledger_id": ID, "tip": tip, "tracking": "local"}}
    # 0133: a security finding still lands in its round.
    assert KEY_A in train_state.record(_state(repo)["exemptions"], "1")  # type: ignore[arg-type]
    _commit(repo, "README.md")
    moved = train_runner.record_exception(repo, ID, CLAIM2, "issue")
    assert moved.code == 1 and "not the integration tip" in moved.lines[0]


# Requirement 4: the push proof admits docs-only commits the docs record covers.


def test_docs_only_commits_pass_with_a_verified_docs_record(repo: Path, plugin: Path) -> None:
    judged = _exempted_security(repo, plugin)
    train = _train(repo)
    worktree = _docs_unit(repo)
    _commit(repo, "README.md")
    current = _commit(repo, "docs/guardrails.md", "docs/howto/README.md")
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"moved past the judged tip {judged[:12]}" in str(info.value)
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is not None
    _verifier_says(repo, worktree, "[VERDICT: VERIFIED] claims=2")
    assert train_runner.record_docs_verdict(repo, "verified").code == 0
    assert push_proof(repo, train) == (
        f"OK approved: every finding exempted, train {train}, round 1, integration tip "
        f"{current[:12]}, docs verified on tip {current[:12]}"
    )
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is None
    moved = _commit(repo, "docs/project-requirements.md")
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"the docs record names tip {current[:12]}, not the current tip {moved[:12]}" in str(
        info.value
    )


def test_a_no_ff_merge_of_the_docs_branch_is_judged_by_its_commits(
    repo: Path, plugin: Path
) -> None:
    # 0131: finish merges the docs branch with --no-ff; the merge and its side commits count.
    _exempted_security(repo, plugin)
    train = _train(repo)
    _git(repo, "switch", "-q", "-c", "docs-side")
    _commit(repo, "docs/howto/README.md")
    _git(repo, "switch", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge docs", "docs-side")
    current = _integration(repo)
    train_state.update(repo, train, docs_verdict={"status": "verified", "tip": current})
    assert push_proof(repo, train).endswith(f"docs verified on tip {current[:12]}")
    _git(repo, "switch", "-q", "docs-side")
    _commit(repo, "scripts/side.py")
    _git(repo, "switch", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "docs-side")
    current = _integration(repo)
    train_state.update(repo, train, docs_verdict={"status": "verified", "tip": current})
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert "changes more than the four public docs" in str(info.value)


def test_a_commit_outside_the_four_docs_is_refused(repo: Path, plugin: Path) -> None:
    judged = _exempted_security(repo, plugin)
    train = _train(repo)
    worktree = _docs_unit(repo)
    _commit(repo, "README.md", "scripts/x.py")
    _verifier_says(repo, worktree, "[VERDICT: VERIFIED] claims=1")
    assert train_runner.record_docs_verdict(repo, "verified").code == 0
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"past the judged tip {judged[:12]} changes more than the four public docs" in str(
        info.value
    )
    reason = gh_policy.verdict_reason(str(repo), "gh pr create")
    assert reason is not None and "changes more than the four public docs" in reason


def test_a_refuted_docs_record_passes_once_every_claim_is_exempted(
    repo: Path, plugin: Path
) -> None:
    _exempted_security(repo, plugin)
    train = _train(repo)
    current = _commit(repo, "README.md")
    train_runner.record_docs_verdict(repo, "refuted", findings=_claims(repo, CLAIM, CLAIM2))
    train_runner.record_exception(repo, ID, CLAIM, "issue")
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"refuted docs claim {CLAIM2} has no exemption, 1 of 2 claims have none" in str(
        info.value
    )
    train_runner.record_exception(repo, ID, CLAIM2, "dropped")
    assert push_proof(repo, train).endswith(
        f"docs refuted with every claim exempted on tip {current[:12]}"
    )
    # 0131: a claim the file gains after the record counts too.
    _claims(repo, CLAIM, CLAIM2, "docs/guardrails.md:3")
    with pytest.raises(ProofError):
        push_proof(repo, train)


def test_an_approved_verdict_admits_docs_commits_through_the_gh_gate(
    repo: Path, plugin: Path
) -> None:
    # 59, 0131: the approved path reads the same rule; no docs record keeps today's refusal.
    judged = _audit_train(repo, plugin)
    train = _train(repo)
    verdict = {"status": "approved", "tip": judged, "round": 1, "seq": 3}
    train_state.update(repo, train, verdict=verdict)
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is None
    current = _commit(repo, "README.md")
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is not None
    state = _state(repo)
    assert tip_admits(repo, train, state, judged, current) is not None
    train_state.update(repo, train, docs_verdict={"status": "verified", "tip": current})
    assert tip_admits(repo, train, _state(repo), judged, current) is None
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is None
    assert tip_admits(repo, train, _state(repo), "z" * 40, current) is not None


def test_the_four_public_docs_are_the_whole_set() -> None:
    assert PUBLIC_DOCS == (
        "README.md",
        "docs/howto/README.md",
        "docs/guardrails.md",
        "docs/project-requirements.md",
    )


# Requirement 3: the Audit section names both verdicts.


def test_the_audit_section_names_the_docs_verdict(tmp_path: Path) -> None:
    state = copy.deepcopy(STATE)
    assert _section(_text(tmp_path, state), "Audit")[-1] == "Docs: not run"
    state["docs_verdict"] = {"status": "verified", "tip": TIP}
    audit = _section(_text(tmp_path, state), "Audit")
    assert (
        audit[0].startswith("[VERDICT: APPROVED]") and audit[-1] == f"Docs: verified on tip {TIP}"
    )
    state["docs_verdict"] = {
        "status": "refuted",
        "tip": TIP,
        "findings": {"a.md:1": {}, "b.md:2": {}},
        "exemptions": {"a.md:1": {"ledger_id": ID, "tip": TIP, "tracking": "local"}},
    }
    audit = _section(_text(tmp_path, state), "Audit")
    docs = audit[
        audit.index(f"Docs: refuted on tip {TIP}; the operator exempted 1 of the 2 claim(s)") :
    ]
    assert docs[1:] == [
        f"- Exempted a.md:1 ({ID}), tracking: Recorded locally",
        f"Deviation: finding a.md:1 exempted with no tracked issue (Recorded locally), "
        f"exemption row {ID}.",
    ]


# Requirements 2 and 5: the recipe, the catalog and the Push Train.


def _flat(rel: str) -> str:
    return " ".join((REPO_ROOT / rel).read_text(encoding="utf-8").split())


def test_the_documentation_stage_records_the_docs_verdict() -> None:
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    stage = " ".join(
        recipe.split("## Documentation stage", 1)[1].split("## Recovery", 1)[0].split()
    )
    verified = stage.split("6. `[VERDICT: VERIFIED]", 1)[1].split(" 7. ", 1)[0]
    finish = "run the Phase 3 step 1 finish"
    record = "daedalus_train.py verdict --repo <repo> --gate docs --status verified`"
    assert verified.index(finish) < verified.index(record) < verified.index("go on to step 8")
    refuted = stage.split("7. `[VERDICT: REFUTED]", 1)[1].split(" 8. ", 1)[0]
    assert (
        "--gate docs --status refuted --findings "
        "<repo>/docs/.tmp/daedalus/<train-id>/docs/findings.txt" in refuted
    )
    assert refuted.index(finish) < refuted.index("--gate docs --status refuted")
    assert "`Exempt the finding`, `Run a fix round` and `End the train`" in refuted
    last = stage.split("8. Summary command and completion:", 1)[1]
    assert "daedalus_train.py summary --repo <repo>` after the docs record" in last
    assert "`[STATUS: TRAIN_COMPLETE]` (Phase 3 step 7) waits on both" in last
    assert "`Docs: not run`" in last
    assert (
        "4. `[STATUS: DOCS_UNCHANGED] reason=<why>`: no claim exists to verify; go on to step 8."
        in stage
    )


def test_the_catalog_names_the_writer_stage_and_its_verifier_pass() -> None:
    catalog = _flat("skills/catalog/SKILL.md")
    audit_row = catalog.split("| Audit |", 1)[1].split("| Commit and release |", 1)[0]
    assert "Then the docs writer stage" in audit_row and "claims pass" in audit_row
    rule = catalog.split("- Docs writer stage (0131, 0134):", 1)[1].split(" - ", 1)[0]
    for part in ("docs-writer", "the verifier checks its claims in a claims pass", "--gate docs"):
        assert part in rule, part
    assert "docs verdict recorded status=<s> tip=<12 hex>" in catalog


def test_the_push_train_carries_no_docs_precondition() -> None:
    push = _flat("skills/push-train/SKILL.md")
    preconditions = push.split("## Recovery round", 1)[0]
    assert "--gate docs" not in push and "docs_verdict" not in push
    step9 = preconditions.split(" 9. ", 1)[1].split(" 10. ", 1)[0]
    assert "`docs verified on tip <12 hex>`" in step9
    assert "the Push Train checks nothing more for the docs" in step9
