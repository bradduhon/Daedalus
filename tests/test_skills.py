# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

SKILLS = sorted((REPO_ROOT / "skills").glob("*/SKILL.md"))
COPYRIGHT = "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"
_SCRIPT_REF = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/scripts/([^\s`\"')]+?\.py)")


def _split(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    block, body = text[4:].split("\n---\n", 1)
    fields: dict[str, str] = {}
    for line in block.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body


def test_skills_exist() -> None:
    assert {p.parent.name for p in SKILLS} >= {
        "doctor",
        "audit-report",
        "build-train",
        "push-train",
    }


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_frontmatter_names_the_directory(path: Path) -> None:
    fields, _ = _split(path)
    assert fields.get("name") == path.parent.name
    assert fields.get("description")


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_copyright_follows_frontmatter(path: Path) -> None:
    _, body = _split(path)
    assert body.splitlines()[0] == COPYRIGHT


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_em_or_en_dashes(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "\u2013" not in text and "\u2014" not in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_named_scripts_exist(path: Path) -> None:
    for name in _SCRIPT_REF.findall(path.read_text(encoding="utf-8")):
        assert (REPO_ROOT / "scripts" / name).is_file(), f"{path}: {name}"


def test_audit_report_names_its_scripts() -> None:
    text = (REPO_ROOT / "skills" / "audit-report" / "SKILL.md").read_text(encoding="utf-8")
    names = set(_SCRIPT_REF.findall(text))
    assert {"audit_report.py", "verify_audit_chain.py"} <= names


def test_script_ref_stops_at_py() -> None:
    # N2: a sentence-ending period after the script name is not part of the name.
    text = "run ${CLAUDE_PLUGIN_ROOT}/scripts/audit_report.py. Then"
    assert _SCRIPT_REF.findall(text) == ["audit_report.py"]


BUILD_TRAIN = REPO_ROOT / "skills" / "build-train" / "SKILL.md"
_AGENT_REF = re.compile(r"Agent\(`([a-z-]+)`\)")


def _build_train() -> str:
    return BUILD_TRAIN.read_text(encoding="utf-8")


def test_build_train_dispatches_existing_agents() -> None:
    names = set(_AGENT_REF.findall(_build_train()))
    for name in names:
        assert (REPO_ROOT / "agents" / f"{name}.md").is_file(), name
    personas = {p.stem for p in (REPO_ROOT / "agents").glob("*.md")}
    # The Push Train owns pr-train-conductor; the Build Train dispatches every other persona.
    assert names == personas - {"pr-train-conductor"}


def test_build_train_probes_the_ledger_and_asks() -> None:
    text = _build_train()
    pre = text.split("## Preconditions", 1)[1].split("## Phase 1", 1)[0]
    assert "append_ledger.py --probe" in pre
    ledger_step = pre.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    assert "append_ledger.py --probe" in ledger_step
    none_found = next(line for line in ledger_step.splitlines() if "none declared" in line)
    assert "ask the operator" in none_found
    assert (
        '"This repo has no decision ledger. Options: name an existing file, or let Daedalus '
        'create docs/decisions.md as a table. Which?"'
    ) in none_found


def test_build_train_routes_every_yield_and_the_contradiction_stop() -> None:
    text = _build_train()
    for route in ("YIELD_WEB", "YIELD_CONTRACT", "YIELD_COMPLIANCE", "YIELD_STANDARDS"):
        assert f"[STATUS: {route}]" in text, route
    assert "[STANDARDS: CONTRADICTION]" in text


def test_build_train_never_pushes() -> None:
    text = _build_train()
    assert "git push" not in text
    assert "--no-ff" in text and "daedalus/<train-id>" in text


def test_build_train_writes_summary_under_docs_tmp() -> None:
    # T7 ruling: the conductor's --body-file reads docs/.tmp, never the data dir.
    text = _build_train()
    assert "<repo>/docs/.tmp/daedalus/<train-id>-summary.md" in text
    assert "docs/.tmp/daedalus/.gitignore" in text
    assert "/daedalus:audit-report" in text


def test_build_train_resolves_the_cache_for_specialists() -> None:
    text = _build_train()
    assert "daedalus_doctor.py --print-cache-dir" in text
    assert "<that path>/frameworks" in text


def test_build_train_stops_on_off_contract_replies_and_dead_hooks() -> None:
    text = _build_train()
    assert "does not end with one of its contract lines or contract sections, stop" in text
    assert "ends with its rule list and has no status line" in text
    assert "the jail is not enforcing. Next: run /daedalus:doctor." in text
    assert "charter: none (repo-local ledger)" in text
    assert "ids=<id>[,<id>]" in text
    assert "Session <id>: .claude/daedalus/audit/<id>.jsonl" in text


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_no_plan_or_task_numbers(path: Path) -> None:
    # R1-M3: operator text never names internal plan or task numbers.
    assert not re.search(r"(Task|Plan) [0-9]", path.read_text(encoding="utf-8"))


def test_build_train_switches_back_after_merge_abort() -> None:
    assert re.search(r"`git merge --abort`, then `git switch <base branch>`", _build_train())


def test_build_train_branches_a_clean_charter_and_switches_back() -> None:
    text = _build_train()
    assert "`git -C <charter_root> status --porcelain`" in text
    assert "`git -C <charter_root> switch -c daedalus/<train-id>`" in text
    assert "`git -C <charter_root> switch <recorded branch>`" in text


def test_build_train_checks_the_probe_record_in_the_audit_log() -> None:
    step = _build_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "audit log" in step
    assert '"event":"PreToolUse".*"tool_name":"Bash"' in step
    assert "Grep it again with line numbers for `append_ledger.py --probe`" in step
    assert "a `tool_input.command` containing `append_ledger.py --probe`" in step
    assert "Never Read the whole log." in step


def test_build_train_records_the_charter_branch_and_switches_back_on_every_stop() -> None:
    # R2-M2, R2-M3: record before switch -c; switch back before every later stop.
    text = _build_train()
    record = re.search(r"record the Charter's current branch with `([^`]+)`", text)
    assert record and record.group(1) == "git -C <charter_root> rev-parse --abbrev-ref HEAD"
    assert "Charter switch-back: once Preconditions step 7 has created the Charter branch" in text
    step = text.split("`[STATUS: COMMITTED] <sha>", 1)[1].split("\n5. ", 1)[0]
    for stop in (
        "LEDGER_MISMATCH] expected=<n> ledger=<m>`: Charter switch-back",
        "Any other reply: Charter switch-back",
    ):
        assert stop in step, stop
    assert "Otherwise Charter switch-back, then stop and show the detail." in step
    # M7: the rule's command and the MISMATCH switch-on.
    assert (
        "run `git -C <charter_root> switch <recorded branch>` before every stop that follows"
        in text
    )
    assert "the train runs `git -C <charter_root> switch daedalus/<train-id>`" in step


def test_build_train_keeps_a_dirty_charter_ledger_on_the_train_branch() -> None:
    # Ruling M8: a modified ledger after BLOCKED stays on daedalus/<train-id>.
    step = _build_train().split("`[STATUS: BLOCKED] <detail>`:", 1)[1].split("\n5. ", 1)[0]
    assert step.lstrip().startswith(
        "when you created a Charter branch, run `git -C <charter_root> status --porcelain` first."
    )
    assert "If it lists the ledger file, stop without the switch-back" in step


def test_build_train_summary_names_every_charter_form() -> None:
    text = _build_train()
    assert (
        "charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> "
        "(ledger under charter_root)"
    ) in text
    assert (
        "charter: <charter name>, branch daedalus/<train-id>, charter base: <recorded branch> "
        "(ledger repo-local)"
    ) in text
    assert "no charter branch" not in text
    assert "Ledger: <ledger repo name>/<ledger path relative to that repo>." in text
    # N2: the I2 sentence that defines <charter name>.
    assert "`<charter name>` is the last component of `charter_root`" in text


def test_build_train_summary_carries_no_absolute_path() -> None:
    # I2: the summary is a public PR body.
    shape = _build_train().split("Shape:", 1)[1].split("\n6. ", 1)[0]
    lines = [ln for ln in shape.splitlines() if "charter:" in ln or "Ledger:" in ln]
    assert len(lines) == 4
    lines += [ln for ln in shape.splitlines() if "Contract:" in ln]
    assert len(lines) == 6
    for line in lines:
        assert "<path>" not in line and "<charter_root>" not in line and "/home" not in line


def test_build_train_reads_the_auditor_verdict_first() -> None:
    text = _build_train()
    assert "Read the verdict from the first line of the auditor's reply." in text
    # N2: the off-contract rule names the first-line exception.
    assert (
        "The security-auditor's verdict line is the first line of its reply, not the last; "
        "read it there."
    ) in text
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    contract = auditor.split("## Status contract", 1)[1]
    assert "starts with exactly one of these verdict lines as its first line" in contract


PUSH_TRAIN = REPO_ROOT / "skills" / "push-train" / "SKILL.md"


def _push_train() -> str:
    return PUSH_TRAIN.read_text(encoding="utf-8")


def test_push_train_dispatches_only_the_conductor() -> None:
    assert set(_AGENT_REF.findall(_push_train())) == {"pr-train-conductor"}


def test_push_train_leaves_the_merge_to_the_operator() -> None:
    text = _push_train()
    assert "never merge" in text.lower() or "operator merges" in text
    assert "gh pr merge" not in text
    assert "--force" not in text


def test_push_train_uses_the_conductor_push_grammar_and_scan() -> None:
    text = _push_train()
    assert "git push -u origin" in text
    assert "gitleaks detect" in text
    assert "gitleaks version" in text
    assert "--body-file <repo>/docs/.tmp/daedalus/<train-id>-summary.md" in text


def test_push_train_checks_the_audit_chain_and_the_summary() -> None:
    text = _push_train()
    assert "verify_audit_chain.py" in set(_SCRIPT_REF.findall(text))
    assert "docs/.tmp/daedalus/" in text
    assert "Next: run /daedalus:build-train first." in text
    assert "a `tool_input.command` of `git status --porcelain`" in text
    assert "[VERDICT: APPROVED]" in text


def test_push_train_ends_with_the_operator_checklist() -> None:
    hand_off = _push_train().split("## Hand-off", 1)[1]
    for item in ("1. Review", "2. Check CI", "3. Merge"):
        assert item in hand_off, item
    # M2: leave the train branch before deleting it, in both repos.
    assert (
        "4. Run `git switch <base branch>`, then delete the branch with "
        "`git branch -d daedalus/<train-id>`."
    ) in hand_off
    assert (
        "then run `git -C <charter_root> switch <charter base>` and "
        "`git -C <charter_root> branch -d daedalus/<train-id>`."
    ) in hand_off
    assert "5. Run `/daedalus:audit-report <session>`" in hand_off


def test_build_train_names_the_push_train_in_present_tense() -> None:
    text = _build_train()
    assert "/daedalus:push-train" in text
    assert "Push Train will" not in text and "adds the Push Train" not in text
    assert "A later Daedalus release adds `/daedalus:push-train`" not in text


def test_push_train_reads_the_auditor_record_with_an_escaped_pattern() -> None:
    # I1: a bare [VERDICT: APPROVED] is a regex character class.
    step = _push_train().split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    assert r"`\[VERDICT: APPROVED\]`" in step
    # Ruling N1: the exact namespaced value the log stores; no bare form, no wildcard.
    assert '`"agent_type":"daedalus:security-auditor".*"event":"SubagentStop"`' in step
    assert '"agent_type":"security-auditor"' not in step
    # Ruling N4: the last auditor record before this train's summary Write.
    assert r'`<train-id>-summary\.md.*"tool_name":"Write"`' in step
    assert "take the last match before that summary line" in step
    assert "square brackets are escaped" in step
    assert "`last_message_head` starts with `[VERDICT: APPROVED]`" in step


def test_push_train_stops_on_each_precondition() -> None:
    pre = _push_train().split("## Preconditions", 1)[1].split("## Push", 1)[0]
    for stop in (
        "No file: stop. Next: run /daedalus:build-train first.",
        "Anything but `daedalus/<train-id>`: stop.",
        "Any `??` line or any change in column two: stop.",
        "A `BROKEN` line: stop and show that line only.",
        "the second an empty line, because the conductor's body files must sit under",
    ):
        assert stop in pre, stop


def _section(text: str, head: str, nxt: str) -> str:
    return text.split(head, 1)[1].split(nxt, 1)[0]


def test_build_train_saves_and_commits_the_contract() -> None:
    # 0011: the packet is saved and committed; the summary records path and version.
    text = _build_train()
    phase1 = _section(text, "## Phase 1", "## Phase 2")
    assert '"Save the packet to <contract path>, then end the reply with the packet."' in phase1
    assert "Run `git switch -c daedalus/<train-id>`: the integration branch" in phase1
    assert phase1.index("git switch -c daedalus/<train-id>") < phase1.index(
        "Agent(`contract-spec`)"
    )
    assert "The main session owns this commit; contract-spec never commits." in phase1
    assert '`git commit -m "Lock contract <name> v<packet_version>"`' in phase1
    assert '`git -C <charter_root> commit -m "Lock contract <name> v<packet_version>"`' in phase1
    assert "Glob the contract path. No file: stop. Next: rerun `/daedalus:build-train`" in phase1
    phase2 = _section(text, "## Phase 2", "## Phase 3")
    assert '"Save the revised packet to <contract path>, overwriting it,' in phase2
    assert "with the message `Revise contract <name> v<N>`" in phase2
    assert "       Contract: contracts/<name>.md v<packet_version>\n" in text
    assert "Contract: <charter name>/specs/<name>.md v<packet_version>\n" in text
    rule = (
        "The Build Train saves the Locked Contract Packet to a file and the main session commits it"
    )
    assert rule in text
    assert "a Build Train keeps the packet in the reply" not in text
    # R3-M2: the howto carries the same sentence.
    howto = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    assert (
        "saves the Locked Contract Packet to a file, and the train's main session commits it"
        in (howto)
    )
    assert "committed on the integration branch `daedalus/<train-id>` before any coder starts" in (
        howto
    )
    assert "a Build Train keeps the packet in the reply" not in howto


def test_build_train_skips_the_commit_for_an_unchanged_contract() -> None:
    # Ruling 2: file exists, add, then diff --cached --quiet; rc 0 skips the commit.
    phase1 = _section(_build_train(), "## Phase 1", "## Phase 2")
    repo = phase1.split("   - In this repo:", 1)[1].split("\n", 1)[0]
    order = [
        "Glob the contract path",
        "`git add contracts/<name>.md`",
        "`git diff --cached --quiet -- contracts/<name>.md`",
        "Exit 0: the file is unchanged; skip the commit and note `contract unchanged, no commit`.",
        '`git commit -m "Lock contract <name> v<packet_version>"`',
    ]
    assert [repo.index(s) for s in order] == sorted(repo.index(s) for s in order)
    charter = phase1.split("   - In the Charter:", 1)[1].split("\n", 1)[0]
    order = [
        "`git -C <charter_root> add specs/<name>.md`",
        "`git -C <charter_root> diff --cached --quiet -- specs/<name>.md`",
        "Exit 0: skip the commit with the same note.",
        '`git -C <charter_root> commit -m "Lock contract <name> v<packet_version>"`',
    ]
    assert [charter.index(s) for s in order] == sorted(charter.index(s) for s in order)
    assert "git status --porcelain -- contracts/<name>.md`. No output" not in phase1


def test_build_train_refuses_a_revision_that_does_not_raise_the_version() -> None:
    # R4-M2: N must exceed the recorded packet_version before the Revise commit.
    phase2 = _section(_build_train(), "## Phase 2", "## Phase 3")
    # R5-I2: one retry, then the second non-increasing version stops.
    stop = (
        "When <N> is not greater than the State Block packet_version <n>, "
        'SendMessage(contract-spec, "packet_version must exceed <n>; revise and save again") '
        "once. A second reply whose <N> is still not greater stops the train: the worktree "
        "teardown listing first, then the uncommitted-contract Next:."
    )
    assert stop in phase2
    assert phase2.index(stop) < phase2.index("`Revise contract <name> v<N>`")


def test_build_train_branches_the_charter_in_preconditions() -> None:
    # 0011: every Charter write of the train lands on the train branch.
    text = _build_train()
    pre = _section(text, "## Preconditions", "## Phase 1")
    step7 = pre.split("\n7. ", 1)[1]
    assert step7.startswith("When `charter_root` is declared, run `git -C <charter_root> status")
    assert "`git -C <charter_root> switch -c daedalus/<train-id>`" in step7
    assert step7.index("rev-parse --abbrev-ref HEAD") < step7.index("switch -c")
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert "switch -c" not in phase3
    assert "it is empty when the contract commit landed" in phase3
    assert "Integration switch-back: once Phase 1 step 2 has created" in text
    # R4-M3: the howto says where the Charter branch comes from.
    howto = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    assert (
        "The train creates the Charter's `daedalus/<train-id>` branch in its checks, for the "
        "contract and ledger commits"
    ) in howto


def test_build_train_audits_from_the_integration_branch() -> None:
    # R4-C1: the contract commits sit on daedalus/<train-id>, outside every unit diff.
    phase3 = _section(_build_train(), "## Phase 3", "\n3. ")
    step2 = phase3.split("\n2. ", 1)[1]
    dispatch = step2.split("Then Agent(`security-auditor`) with:", 1)[1].split(". Read", 1)[0]
    assert dispatch.startswith(" the diff base `daedalus/<train-id>`, so each diff leaves out")
    assert "base commit" not in dispatch and "base sha" not in dispatch
    step1 = phase3.split("\n2. ", 1)[0]
    assert "(`git diff daedalus/<train-id>...<branch>`)" in step1
    assert "<base sha>" not in step1
    auditor = (REPO_ROOT / "agents" / "security-auditor.md").read_text(encoding="utf-8")
    assert "For each branch run `git diff <diff base>...<branch>`" in auditor


def test_build_train_keeps_dirty_trees_on_the_train_branch() -> None:
    # Ruling 1, R4-I1: a dirty Charter or an uncommitted contract takes no switch-back.
    text = _build_train()
    rules = text.split("## Preconditions", 1)[0]
    assert (
        "The exception: any stop while the Charter tree is dirty (`git -C <charter_root> status "
        "--porcelain` prints anything) takes no Charter switch-back"
    ) in rules
    assert "The one exception is a charter-docs BLOCKED" not in rules
    assert (
        "- Uncommitted contract: any stop while the contract file is uncommitted "
        "(`git status --porcelain -- contracts/<name>.md`, or `git -C <charter_root> status "
        "--porcelain -- specs/<name>.md`, prints its path) takes neither switch-back."
    ) in rules
    assert "The stop names the file and says it sits on `daedalus/<train-id>` in its repo." in rules
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert (
        "Any output: stop without the Charter switch-back, because the Charter tree is dirty"
        in (phase3)
    )
    assert "Any output: Charter switch-back" not in phase3
    # R5-I1: the dirty-Charter stop overrides the global Next: and resumes on the train branch.
    dirty = phase3.split("Any output: stop without the Charter switch-back", 1)[1].split("\n", 1)[0]
    assert "This Next: overrides the dirty-Charter Next: in the rules above." in dirty
    assert (
        "leave the Charter on that branch, then say continue; the train runs "
        "`git -C <charter_root> switch daedalus/<train-id>` and resumes at this step."
    ) in dirty
    assert (
        "Any other reply: Charter switch-back, none while the Charter tree is dirty, then the "
        "off-contract stop."
    ) in phase3


def test_build_train_keeps_worktrees_out_of_git_and_the_train() -> None:
    # R3-O1, R4-I3, R4-M1: worktrees are ignored, listed, force-removed on every exit.
    text = _build_train()
    assert (
        "if `<repo>/.claude/worktrees/.gitignore` is absent write it with the single line `*`"
        in (text)
    )
    rules = text.split("## Preconditions", 1)[0]
    teardown = rules.split("- Worktree teardown: ", 1)[1].split("\n", 1)[0]
    assert teardown.startswith(
        "worktrees never outlive the train. Before every stop once Phase 2 has begun, and after "
        "the merges in Phase 3 step 4,"
    )
    order = [
        "show `git -C <path> status --porcelain` (the changes being discarded)",
        "run `git worktree remove --force <path>`",
        "then `git worktree prune` once at the end",
    ]
    assert [teardown.index(s) for s in order] == sorted(teardown.index(s) for s in order)
    assert "they are discarded, never committed." in teardown
    # R5-C1: only the State Block's unit branches are torn down.
    assert (
        "the scope is only the unit branches recorded in the State Block, each matched by its "
        "branch name in `git worktree list --porcelain`. Any other worktree under "
        "`<repo>/.claude/worktrees/` is left untouched and never listed for discard."
    ) in teardown
    phase3 = _section(text, "## Phase 3", "\n5. The summary")
    assert "After the merges succeed, run the worktree teardown." in phase3
    assert phase3.index("worktree teardown") < phase3.index("Agent(`charter-docs`)")
    assert "A remove failure: Charter switch-back, then stop" in phase3
    assert "commit or discard the changes in the worktree" not in text


def test_push_train_hands_off_the_contract_commits() -> None:
    # 0011: the contract commits ride the pushed branches; no new conductor command.
    pt = _push_train()
    assert "the contract path and version from the `Contract:` line" in pt
    assert "when the `charter:` line ends in `(ledger under charter_root)`" in pt
    hand_off = pt.split("## Hand-off", 1)[1]
    assert "its `Lock contract` and `Revise contract` commits are part of the diff" in hand_off
    assert "the contract commits are in this pull request" in hand_off
    assert "contract" not in _section(pt, "## Push", "## Charter branch").lower()


def test_push_train_names_the_charter_pull_request_by_its_content() -> None:
    # Ruling 3: title and body split on where the ledger lives.
    pt = _push_train()
    body = _section(pt, "## Charter branch", "## Hand-off")
    ledger = body.split("(ledger under charter_root)`:", 1)[1].split("Otherwise:", 1)[0]
    assert "    Contract and ledger entries for Build Train <train-id>.\n" in ledger
    other = body.split("Otherwise:", 1)[1]
    assert "    Contract for Build Train <train-id>.\n" in other
    assert "ledger" not in other.split("The conductor", 1)[0]
    hand_off = pt.split("## Hand-off", 1)[1]
    assert (
        "where `<title>` is `Build Train <train-id>: contract and ledger` when the `charter:` line "
        "ends in `(ledger under charter_root)`, else `Build Train <train-id>: contract`."
    ) in hand_off


def test_push_train_checks_the_remote_before_the_conductor() -> None:
    # F5: the conductor's hook refuses git remote, so the main session checks origin.
    text = _push_train()
    pre = text.split("## Preconditions", 1)[1].split("## Push", 1)[0]
    assert "run `git remote get-url origin` before any conductor dispatch" in pre
    assert "A non-zero exit: stop. Next: add a remote named origin, then rerun." in pre
    dispatch = text.split("## Push", 1)[1].split("\n2. ", 1)[0]
    assert "The remote `origin` exists" in dispatch
    assert "Never repeat the URL it prints to the operator; a remote URL can carry a token." in pre
    assert text.index("git remote get-url origin") < text.index("Agent(`pr-train-conductor`)")


def test_push_train_validates_the_train_id_against_build_train() -> None:
    # Ruling M11: the format comes from build-train Preconditions step 6.
    assert "`<train-id>` to the UTC time as `YYYYMMDD-HHMMSS`" in _build_train()
    text = _push_train()
    assert "`^[0-9]{8}-[0-9]{6}$`, the UTC `YYYYMMDD-HHMMSS` form" in text
    assert "No match: stop." in text


def test_push_train_dispatch_pins_flags_and_paths() -> None:
    text = _push_train()
    assert "gitleaks detect --redact --log-opts=<base sha>..daedalus/<train-id>" in text
    for forbidden in (
        "Never run `git commit -a`",
        "`git commit -am`",
        "never `gh pr edit --base`",
        "never `gh pr create --body`",
    ):
        assert forbidden in text, forbidden
    assert '"Use only the commands above. Never run' in text
    # M9: every body file is absolute under <repo>.
    paths = re.findall(r"--body-file (\S+?)`", text)
    assert len(paths) == 4
    for path in paths:
        assert path.startswith("<repo>/docs/.tmp/daedalus/<train-id>-"), path


def test_push_train_routes_ci_without_waiting() -> None:
    text = _push_train()
    assert "`gh run list --branch daedalus/<train-id> --commit <that sha>`" in text
    assert "`[STATUS: CI] run=none conclusion=no workflow runs`" in text
    assert "`run=none`, or a `[STATUS: PUSHED]` reply, means no CI was reported." in text
    # Ruling (CI conclusions): only success, skipped and neutral pass; the rest stop.
    assert "any run whose conclusion is not `success`, `skipped` or `neutral`" in text
    assert "   - Conclusion `success`: go on.\n" in text
    # N5-M3: every non-success conclusion is named, even when a later run succeeded.
    assert (
        "where `<text>` lists every conclusion other than `success` seen across the "
        "listed runs, comma-separated"
    ) in text
    assert (
        "Conclusion `skipped`, `neutral`, or a comma-separated list of only those two: "
        "go on, and name every listed conclusion in hand-off item 2."
    ) in text
    assert "else the last run" not in text
    stop = next(ln for ln in text.splitlines() if "Any other conclusion, known or not" in ln)
    assert "`startup_failure`" in stop and "show them, and stop." in stop
    assert "report it and go on" not in text
    assert "Deviation: CI not observed at push time" in text
    assert "`CI not observed; check the PR's checks before merging`" in text


def test_both_trains_carry_the_pending_ledger_line() -> None:
    # Ruling N3: the summary exists before charter-docs; push-train refuses it pending.
    bt = _build_train()
    assert "with the line `Ledger ids: pending. Codes: --repo <R> --type <T>.`" in bt
    assert "replace the summary's `Ledger ids: pending` line with" in bt
    assert bt.index("Write the summary now") < bt.index("Agent(`charter-docs`)")
    pt = _push_train()
    assert "A `Ledger ids: pending` line means the Build Train stopped before" in pt
    assert "run `git -C <charter_root> switch daedalus/<train-id>` first." in pt
    assert "A later Daedalus release adds a Build Train resume for this step." in pt
    # N5-M4: the pending Next: writes the same line build-train writes, period included.
    assert "replace that line with `Ledger ids: <ids> in commit <sha>.`, switch" in pt
    assert "with `Ledger ids: <ids> in commit <sha>.` using the Edit tool" in bt
    # N5-M2: the Charter dirty-tree stop precedes the summary write.
    assert "Every stop after this point leaves a summary." in bt
    assert "Every stop after the merge" not in bt


def test_push_train_reads_the_ledger_sha_from_the_ledger_ids_line() -> None:
    # N5-M1: the summary's `Ledger:` line is the path; the sha is on `Ledger ids:`.
    step = _push_train().split("\n3. ", 1)[1].split("\n4. ", 1)[0]
    assert "the ledger commit sha from the `Ledger ids:` line," in step


def test_push_train_stops_without_an_approved_audit() -> None:
    # N5-M1: precondition 9 names each missing record and its stop.
    step = _push_train().split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    assert step.rstrip().endswith(
        "No summary Write record, no auditor SubagentStop record before it, or any other "
        "verdict: stop. Next: run /daedalus:build-train; this train has no approved audit "
        "in its log."
    )


def test_push_train_hands_the_charter_to_the_operator() -> None:
    hand_off = _push_train().split("## Hand-off", 1)[1]
    assert "`git -C <charter_root> push -u origin daedalus/<train-id>`" in hand_off
    assert (
        "`gh pr create --base <charter base> --head daedalus/<train-id> --title "
        '"<title>" --body-file '
        "<repo>/docs/.tmp/daedalus/<train-id>-charter-pr.md`"
    ) in hand_off
    assert hand_off.rstrip().endswith(
        "Execution Train readiness: a later Daedalus release adds the readiness checklist."
    )
    assert "The train does not stop here; go on to the hand-off." in _push_train()


# Fix wave after the whole-branch review (C1, I2, M4).
BASE_REF_STOP = (
    '"Unit <b> does not descend from the integration branch; worktrees are branching from the '
    "default branch. Next: set worktree.baseRef to head in your settings (run /daedalus:doctor) "
    'and rerun the train."'
)


def test_build_train_checks_each_unit_descends_from_the_lock() -> None:
    text = _build_train()
    assert "packet_version: <n>  contract: <contract path>  lock: <sha>" in text
    phase1 = text.split("## Phase 1", 1)[1].split("## Phase 2", 1)[0]
    assert "Run `git rev-parse daedalus/<train-id>` and record it as `lock: <sha>`" in phase1
    assert "coders branch from it when `worktree.baseRef` is `head`" in phase1
    complete = next(line for line in text.splitlines() if line.startswith("| `[STATUS: COMPLETE]"))
    check = "Run `git merge-base --is-ancestor <lock sha> <b>` with the State Block `lock:` sha."
    assert check in complete
    assert f"A non-zero exit: stop with {BASE_REF_STOP} Otherwise record branch" in complete


def test_build_train_never_respawns_a_coder() -> None:
    text = _build_train()
    assert "Continue on branch" not in text
    assert (
        '"Coder for unit <b> cannot be resumed. Next: rerun the train; the unit branch <b> is '
        'kept for reference."'
    ) in text
    assert "If SendMessage to a coder fails, never start a replacement coder" in text


def test_build_train_liveness_uses_no_bash() -> None:
    # M4: a Bash call here would become the newest Bash record and void the check.
    step = _build_train().split("\n5. ", 1)[1].split("\n6. ", 1)[0]
    assert "Use only the Glob, Grep and Read tools here, no Bash" in step


_SKILL_SCRIPT = re.compile(r"`(python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/[^`]+)`")


def test_skill_script_commands_are_allowed_for_main() -> None:
    # M4: every plugin script command in the trains passes the jail as the main session.
    from lib.config import Config
    from lib.jail import decide

    root = str(REPO_ROOT)
    commands = [
        re.sub(r"<[^>]+>", "x", m.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("<repo>", root))
        for path in (REPO_ROOT / "skills" / "build-train", REPO_ROOT / "skills" / "push-train")
        for m in _SKILL_SCRIPT.findall((path / "SKILL.md").read_text(encoding="utf-8"))
    ]
    assert len(commands) >= 4
    for command in commands:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root}
        d = decide(payload, Config())
        assert d.allow, (command, d.reason)
