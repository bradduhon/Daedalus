# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0278: a verifier round after a refutation reads the commits since the judged tip and each place.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import train_runner, train_state

from tests.conftest import CFG, CWD, REPO_ROOT, SCRIPTS_DIR, WT, git
from tests.hook_chain import decide
from tests.payloads import _b
from tests.test_fix_units import _fix, _merged
from tests.test_fix_units import _fixture as fix_fixture
from tests.test_records_in_one_call import TRAIN, _built, _cli, _fixture, _ok, _verdict
from tests.test_records_in_one_call import fixed as fixed  # noqa: F401
from tests.test_workspace_train import VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
ROW_ONE = (
    "code | req 1 | MISSING | none | Refuse x. | rule: x is refused at the guard | "
    "places: u1.txt:1, scripts/lib/jail.py:guard | search: git grep -n x"
)
ROW_TWO = (
    "scope | files | WIDENED | extra.txt | the files list | rule: only listed files change | "
    "places: extra.txt:1 | search: git diff --name-only"
)
ROW_THREE = (
    "code | req 2 | NARROWED | y | Admit y. | rule: y is admitted | places: u1.txt:fix | "
    "search: git grep -n y"
)
PLACES_ONE_TWO = [
    "Place: u1.txt:1 | rule: x is refused at the guard",
    "Place: scripts/lib/jail.py:guard | rule: x is refused at the guard",
    "Place: extra.txt:1 | rule: only listed files change",
]


def _reply(*rows: str) -> str:
    line = f"[VERDICT: REFUTED] {'; '.join(rows)}"
    return f"{line}\n| claim | result |\ncorrected=0\n{line}\n"


def _branch(uid: str) -> str:
    return f"daedalus-unit/{TRAIN}-{uid.lower()}"


def _tip(root: Path, uid: str) -> str:
    return git(root, "rev-parse", _branch(uid)).stdout.strip()


def _commit(path: Path, name: str) -> str:
    (path / f"{name}.txt").write_text(f"{name}\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", f"fix {name}")
    return git(path, "rev-parse", "HEAD").stdout.strip()


def _assets(root: Path, uid: str, tip: str | None = None) -> tuple[int, list[str]]:
    lock = str(train_state.load(root, TRAIN)["lock_sha"])
    code, out = _cli(root, "assets", "--base", lock, "--tip", tip or _branch(uid), "--unit", uid)
    return code, out.splitlines()


def _state_bytes(root: Path) -> bytes:
    return train_state.state_path(root, TRAIN).read_bytes()


def _refuted_u1(root: Path, *rows: str) -> tuple[Path, str]:
    _ok(train_runner.dispatch_unit(root, "U1"))
    unit = _built(root, "U1")
    _verdict(root, unit, _reply(*rows))
    _ok(train_runner.route_unit(root, "U1", "REFUTED"))
    return unit, _tip(root, "U1")


def test_round_one_prints_no_range_and_each_fix_round_starts_at_its_verdicts_tip(
    tmp_path: Path,
) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    unit = _built(root, "U1")
    assert _assets(root, "U1") == (0, ["Assets: none"])
    _verdict(root, unit, _reply(ROW_ONE, ROW_TWO))
    _ok(train_runner.route_unit(root, "U1", "REFUTED"))
    judged = _tip(root, "U1")
    first = _commit(unit, "fix1")
    code, lines = _assets(root, "U1")
    assert code == 0 and lines == ["Assets: none", f"Range: {judged}..{first}", *PLACES_ONE_TWO]
    assert git(root, "rev-list", f"{judged}..{first}").stdout.split() == [first]
    # The second refutation judged the first fix's tip; its range holds the second fix alone.
    _verdict(root, unit, _reply(ROW_THREE))
    _ok(train_runner.route_unit(root, "U1", "REFUTED"))
    second = _commit(unit, "fix2")
    code, lines = _assets(root, "U1")
    place = "Place: u1.txt:fix | rule: y is admitted"
    assert code == 0 and lines == ["Assets: none", f"Range: {first}..{second}", place]
    recorded = train_state.units(train_state.load(root, TRAIN))
    tips = next(u for u in recorded if u["name"] == f"{TRAIN}-u1")[train_runner.JUDGED_TIPS]
    assert list(tips.values()) == [judged, first]  # type: ignore[union-attr]


def test_two_rows_naming_three_places_print_three_place_lines_in_row_order(
    tmp_path: Path,
) -> None:
    root = _fixture(tmp_path / "repo")
    unit, _ = _refuted_u1(root, ROW_ONE, ROW_TWO)
    _commit(unit, "fix1")
    lines = _assets(root, "U1")[1]
    assert [ln for ln in lines if ln.startswith("Place: ")] == PLACES_ONE_TWO


def test_an_empty_range_is_refused_and_leaves_the_state(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    _refuted_u1(root, ROW_ONE)
    before = _state_bytes(root)
    code, lines = _assets(root, "U1")
    assert code == 1 and "has no commit since the refuted verdict" in lines[0], lines
    assert "Next:" in lines[0]
    assert not any(ln.startswith(("Range: ", "Assets: ")) for ln in lines)
    assert _state_bytes(root) == before


def test_a_rewritten_branch_is_refused_and_leaves_the_state(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    unit, judged = _refuted_u1(root, ROW_ONE)
    git(unit, "reset", "-q", "--hard", f"{judged}~1")
    _commit(unit, "rewritten")
    before = _state_bytes(root)
    code, lines = _assets(root, "U1")
    assert code == 1 and "is not an ancestor" in lines[0] and "Next:" in lines[0], lines
    assert _state_bytes(root) == before


def test_a_tip_that_is_not_the_units_is_refused(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    unit, _ = _refuted_u1(root, ROW_ONE)
    _commit(unit, "fix1")
    code, lines = _assets(root, "U1", tip=f"daedalus/{TRAIN}")
    assert code == 1 and "is neither unit U1's branch" in lines[0] and "Next:" in lines[0]
    assert _assets(root, "U1", tip=_tip(root, "U1"))[0] == 0


def test_an_operator_check_fail_prints_the_range_and_no_place(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    unit = _built(root, "U1")
    _verdict(root, unit, VERIFIED_REPLY)
    _ok(train_runner.refuted(root, "U1", "The page shows the title"))
    judged = _tip(root, "U1")
    fixed_tip = _commit(unit, "fix1")
    assert _assets(root, "U1")[1] == ["Assets: none", f"Range: {judged}..{fixed_tip}"]


def test_a_refutation_recorded_without_a_tip_reads_the_whole_unit(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    unit, _ = _refuted_u1(root, ROW_ONE)
    _commit(unit, "fix1")

    def drop(state: dict[str, object]) -> None:
        for each in state["units"]:  # type: ignore[attr-defined]
            each.pop(train_runner.JUDGED_TIPS, None)

    train_state.change(root, TRAIN, drop)
    assert _assets(root, "U1") == (0, ["Assets: none"])


def test_a_fix_units_first_verifier_round_prints_no_range(tmp_path: Path) -> None:
    root = _merged(fix_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    _ok(train_runner.dispatch_unit(root, "fix1-u1"))
    _built(root, "fix1-u1")
    assert _assets(root, "fix1-u1") == (0, ["Assets: none"])


def test_the_orchestrator_runs_assets_with_unit() -> None:
    script = SCRIPTS_DIR / "daedalus_train.py"
    command = f"python3 {script} assets --repo {CWD} --base abc123 --tip b --unit U1"
    assert decide(_b("orchestrator", command), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        f"git -C {WT} diff {'a' * 40}..{'b' * 40}",
        f"git -C {WT} log --oneline {'a' * 40}..{'b' * 40}",
        f"git -C {WT} diff {'a' * 40}..{'b' * 40} -- u1.txt",
        f"git -C {WT} show {'b' * 40}:u1.txt",
    ],
)
def test_the_verifier_may_read_a_rounds_range_and_its_places(command: str) -> None:
    assert decide(_b("verifier", command), CFG).allow, command


def test_the_verifier_file_carries_the_later_round_rule_in_four_sentences() -> None:
    text = (REPO_ROOT / "agents" / "verifier.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "Assume no further round: what you return is everything in this submission" in flat
    rule = text.split("\n## Later round\n", 1)[1].strip()
    assert "\n## " not in rule and rule.count(". ") + 1 <= 4, rule
    for part in ("`Range: <sha>..<sha>`", "whether it is fixed", "Read nothing else"):
        assert part in rule, part
