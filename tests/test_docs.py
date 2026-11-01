# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# B7: every key an operator file reader accepts appears in docs/project-requirements.md.
from __future__ import annotations

import json
import re
import subprocess
from pathlib import PurePosixPath

import standing_rules
from lib import train_definition
from lib.project_keys import manifest_keys
from lib.train_scope import policed_outside_train

from tests.conftest import REPO_ROOT

REQUIREMENTS = REPO_ROOT / "docs" / "project-requirements.md"
_HAND_ROW = re.compile(r"^\| `([^`]+)` \|", re.MULTILINE)
# 0069: entrypoints is a free map of area names, so the block itself is the key.
_OPAQUE = frozenset({"entrypoints"})


def _section(heading: str) -> str:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert text.count(f"\n{heading}\n") == 1, heading
    body = text.split(f"\n{heading}\n", 1)[1]
    return re.split(r"\n#{2,3} ", body, maxsplit=1)[0]


def _leaves(value: object, prefix: str = "") -> set[str]:
    if not isinstance(value, dict) or prefix in _OPAQUE:
        return {prefix}
    out: set[str] = set()
    for key, inner in value.items():
        out |= _leaves(inner, f"{prefix}.{key}" if prefix else str(key))
    return out


def test_backfill_keys_and_areas_are_documented() -> None:
    section = _section("### Standing-rules backfill file")
    for key in sorted(
        standing_rules.BACKFILL_KEYS
        | standing_rules.OPTIONAL_BACKFILL_KEYS
        | standing_rules.RELATION_KEYS
    ):
        assert f"`{key}`" in section, key
    for area in standing_rules.AREAS:
        assert f"`{area}`" in section, area


def test_train_definition_keys_are_documented() -> None:
    section = _section("### Project train definitions")
    keys = (
        train_definition.TOP_FIELDS
        + train_definition.STAGE_FIELDS
        + train_definition.OPTIONAL_STAGE_FIELDS
        + train_definition.SCOPE_FIELDS
        + train_definition.PROOF_FIELDS
        + train_definition.PATH_CLASSES
    )
    for key in keys:
        assert f"`{key}`" in section, key
    assert f'`"{train_definition.PER_UNIT}"`' in section


def _tree() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("\n## What is in this repo\n", 1)[1]
    return section.split("```\n", 1)[1].split("```", 1)[0]


def test_readme_tree_names_every_agent_skill_and_script() -> None:
    # B7: a file added under agents/, skills/ or scripts/ must appear in the README tree.
    names = set(re.findall(r"[├└]── (\S+)", _tree()))
    missing = []
    for top in ("agents", "skills", "scripts"):
        tracked = subprocess.run(
            ["git", "ls-files", top], cwd=REPO_ROOT, capture_output=True, check=True, text=True
        ).stdout.split()
        for line in tracked:
            rel = PurePosixPath(line).relative_to(top)
            # B7: skills are named by folder, and the controls fragments by their folder.
            if top == "skills":
                want = f"{rel.parts[0]}/SKILL.md"
            elif rel.parts[:2] == ("checks", "controls"):
                want = "checks/controls/"
            else:
                want = rel.as_posix()
            if want not in names:
                missing.append(f"{top}/{rel.as_posix()}")
    assert missing == []


def test_every_manifest_example_key_has_a_row() -> None:
    # B7: a key in the example is a reader key (README table) or a hand row here, never neither.
    section = _section("### service-manifest.json (repo root), optional **(checked)**")
    example = json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])
    hand = set(_HAND_ROW.findall(section))
    readers = set(manifest_keys())
    assert sorted(_leaves(example) - readers - hand) == []
    assert sorted(hand & readers) == [], "a reader key belongs in the generated README table"


def test_readme_outside_train_claim_matches_the_jail() -> None:
    # B8: catalog agents keep their hooks outside a train; the main session is asked, not refused.
    assert policed_outside_train("daedalus:coder")
    stale = (
        "Outside a train, the hooks refuse only reads and searches of credential files",
        "for every agent and the main session",
        "Every agent, and the main session, is refused reads",
        "and the main session while a train runs, are also refused",
    )
    for doc in (REPO_ROOT / "README.md", REPO_ROOT / "docs" / "project-requirements.md"):
        text = doc.read_text(encoding="utf-8")
        assert [claim for claim in stale if claim in text] == [], doc


def test_howto_exemptions_name_the_push_train_exemption_path() -> None:
    # issue 62, 0133: --approved accepts a rejected round whose every finding is exempted.
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    bullet = next(line for line in text.splitlines() if line.startswith("- Skip, track or exempt"))
    assert "by hand" not in bullet and "stops" not in bullet, bullet
    assert (
        "The push run's verdict check accepts a rejected round once every finding in its "
        "findings file carries an exemption."
    ) in text
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "stops at the push run's verdict check" not in readme


def _how_it_works() -> str:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    return text.split("\n## How it works\n", 1)[1].split("\n## ", 1)[0]


def test_readme_how_it_works_walks_a_call_and_a_train() -> None:
    # 0131: one passage per mechanism the coverage map found unexplained, under one section.
    section = _how_it_works()
    heads = re.findall(r"^### (.+)$", section, re.MULTILINE)
    for head in (
        "One tool call, end to end",
        "How a rule set is built from a hooks block",
        "The train marker",
        "The audit log and the reply key",
        "Train state and the bindings file",
        "The push proof",
        "The controls register",
        "One train, end to end",
        "Merges and fix units",
        "The summary's path rule",
        "The kernel wrapper's grants",
    ):
        assert head in heads, head
    for part in (
        "`scripts/enforce_agent_jail.py`",
        "`scripts/lib/train_scope.py`",
        "`scripts/lib/router.py`",
        "`<repo>/.claude/daedalus/reply-hmac.key`",
        "`<repo>/.claude/daedalus/trains/<train-id>.json`",
        "`<repo>/.claude/daedalus/trains/<train-id>.bindings.json`",
        "`python3 <plugin>/scripts/verify_audit_chain.py --approved <train-id> --repo <repo>`",
        "`carries both verdicts`",
        "`scripts/checks/controls/`",
        "`[path withheld]`",
        "`daedalus_confine.py --unit <worktree> -- <command>`",
    ):
        assert part in section, part


def test_readme_how_it_works_names_every_audit_record_type() -> None:
    # 0131: each event hooks.json records, and the events the jail and rotation write.
    section = _how_it_works()
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    events = set(hooks["hooks"]) | {"SubagentHandback", "AuditRotation", "AuditRotationFailed"}
    assert sorted(e for e in events if f"`{e}`" not in section) == []


def test_readme_train_marker_passage_names_the_marker_file() -> None:
    # 0131: one passage lists what the marker switches on, so no effect hides in another section.
    marker = _how_it_works().split("### The train marker", 1)[1].split("\n### ", 1)[0]
    assert "`<repo>/.claude/daedalus/train.active`" in marker
    assert "switches on all of these there" in marker


def test_howto_credential_read_claim_names_the_main_session_warning() -> None:
    # spec 6, Main never prompted (amends 0106): agents are refused, the main session is warned.
    text = (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")
    intro = text.split("## What Daedalus does", 1)[1].split("\n## ", 1)[0]
    assert "It refuses every agent's reads of your credential stores" in intro
    assert "the call runs with a warning in the session's context" in intro
    assert "it asks you first" not in intro
    assert "It refuses reads of your credential stores through file tools" not in intro


def _howto() -> str:
    return (REPO_ROOT / "docs" / "howto" / "README.md").read_text(encoding="utf-8")


def test_howto_checklist_force_deletes_the_train_branch_after_the_merge_check() -> None:
    # issue 19: a squash merge leaves the branch unmerged to git, so -d refuses it.
    checklist = _howto().split("### Your checklist", 1)[1].split("\n### ", 1)[0]
    item4 = checklist.split("\n4. ", 1)[1].split("\n5. ", 1)[0]
    assert item4.index("`gh pr view <url> --json state`") < item4.index(
        "`git branch -D daedalus/<train-id>`"
    )
    assert "from your own shell" in item4
    assert "deletes its branch with `git branch -D`" in checklist
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    push = readme.split("### Push run", 1)[1].split("\n### ", 1)[0]
    assert "`git branch -D daedalus/<train-id>`" in push and "gh pr view <url> --json state" in push


def test_howto_explains_the_recovery_round_and_the_ledger_resume() -> None:
    # 3, 73, spec 6: the recovery paths and the stale agent stop, in the operator's words.
    text = _howto()
    section = text.split("\n## Recovering a train\n", 1)[1].split("\n## ", 1)[0]
    for part in (
        "`reaudit round=<n> tip=<sha>`",
        "no second recovery round runs on the same tip",
        "`Ledger ids: pending`",
        "`resume ledger train=<train-id> summary=<path>`",
        "`stale agents: <names>`",
        "start a new Claude Code session",
    ):
        assert part in section, part
    assert "train recovery" not in text.split("## Sections added by later plans", 1)[1]
    assert "names the ledger resume that finishes it" in text
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "recovery audit round on the new tip (`daedalus_train.py reaudit`)" in readme
    assert "ledger resume (`daedalus_train.py resume`)" in readme
