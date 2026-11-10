# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 204, 107: a read verb or wrapper never writes a file through an option value or operand.
from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
from lib import jail, shell

from tests.adversarial.corpus import (
    A1_EXPANSION,
    A1_EXPANSION_ADMITTED,
    A1_ISSUE_107,
    A1_ISSUE_204,
    A1_READ_ADMITTED,
    A1_READ_P1,
    A1_READ_P2,
    A1_READ_P3,
    A1_READ_P4,
    A1_READ_P9,
    A1_WRAPPER_ROWS,
    CLAIMS_ADMITTED,
    CLAIMS_REFUSED,
    GIT_LOG_COUNT_266,
    GIT_LOG_COUNT_VALUE_266,
    GIT_LOG_SEARCH_269,
    GIT_LOG_SEARCH_VALUE_269,
    LEDGER_CODES_0247,
    REFUSED_FIELDS_HUNT_269,
    S3C_HUNT,
    S3C_HUNT_DECLARED,
    TRACKED_EXCLUDE_267,
    TRACKED_HUNT_267,
    TRACKED_JUDGED_267,
    TRACKED_KEPT_267,
    TRACKED_SECRET_267,
    TRACKED_STAT_267,
    TRACKED_UNKNOWN_267,
    assert_denied,
    tracked_checkouts,
)
from tests.conftest import CFG, CWD, SCRIPTS_DIR, WT
from tests.hook_chain import CHAINS, decide, evaluate, first_deny
from tests.jail_cases import _narrowed_repo
from tests.payloads import _b, _cred, _cwd

pytestmark = pytest.mark.usefixtures("jail_fakes")
READ_ROWS = A1_ISSUE_204 + A1_READ_P1 + A1_READ_P2 + A1_READ_P3 + A1_READ_P4 + A1_READ_P9
# issue 107: the reproduction row with its file in the marked repository.
ISSUE_107 = A1_ISSUE_107.replace("<file>", "{repo}/l").replace("<command>", "true")


@pytest.mark.parametrize("command", READ_ROWS)
def test_a_read_verb_never_writes_through_an_option_or_operand(command: str) -> None:
    # P1 to P4: refused to the auditor, and by the read grammar itself for a read verb.
    assert_denied(_b("auditor", command))
    tokens = shlex.split(command)
    if tokens[0] in shell.READ_ONLY_CMDS:
        assert not jail.admitted(command, "comparer", "/c"), command


@pytest.mark.parametrize("command", A1_EXPANSION)
def test_an_expanding_word_beside_a_writing_read_verb_is_refused(
    marked_repo: Path, command: str
) -> None:
    # P1, 0084: refused to a read-only agent and to an agent Daedalus did not start.
    assert_denied(_b("auditor", command))
    foreign = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(foreign, "read-only while", "could be a credential path")
    assert not jail.admitted(command, "comparer", str(marked_repo)), command


@pytest.mark.parametrize("command", A1_EXPANSION_ADMITTED)
def test_a_quoted_brace_or_glob_is_one_literal_word(marked_repo: Path, command: str) -> None:
    assert jail.admitted(command, "foreign", str(marked_repo)), command
    decision = jail.decide(_cred("Explore", "Bash", str(marked_repo), command=command), CFG)
    assert decision.allow and not decision.warn, (command, decision.reason)
    # O4, prepush2: hygiene and the search glob rule still judge Daedalus agents' other rows.
    if '"' not in command and command.split()[0] in shell.READ_ONLY_WRITE_OPTS:
        decision = decide(_b("auditor", command), CFG)
        assert decision.allow and not decision.warn, (command, decision.reason)


@pytest.mark.parametrize("command", A1_READ_ADMITTED)
def test_a_read_verb_with_one_input_is_admitted(command: str) -> None:
    decision = decide(_b("auditor", command), CFG)
    assert decision.allow and not decision.warn, (command, decision.reason)


@pytest.mark.parametrize("form", (*A1_WRAPPER_ROWS, ISSUE_107))
def test_a_wrapper_file_in_a_marked_repository_is_a_write(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # P9, issue 107, 0224: the wrapper row is unadmitted for an agent, so it scopes nothing
    # from elsewhere; in its own repo the grammar refuses it and names the wrapper.
    command = form.format(repo=marked_repo)
    assert jail._scope_paths(command, str(other_repo)) == (), command
    hook_input = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(hook_input, "read-only while")
    assert "Refused: " in str(jail.decide(hook_input, CFG).reason)


def test_a_coder_creates_no_flock_file_outside_its_worktree() -> None:
    assert_denied(
        _b("coder", A1_ISSUE_107.replace("<file>", "/tmp/l").replace("<command>", "true"))
    )


@pytest.mark.parametrize("command", ["flock 9", "flock -u 9"])
def test_a_lone_numeric_flock_fd_is_no_write(
    marked_repo: Path, other_repo: Path, command: str
) -> None:
    # P9: with no command after it, a numeric operand names a file descriptor, never a path.
    assert not [t for t in jail._scope_paths(command, str(other_repo)) if str(marked_repo) in t]
    decision = jail.decide(_cred("Explore", "Bash", str(other_repo), command=command), CFG)
    assert decision.allow and not decision.warn, decision.reason


@pytest.mark.parametrize("command", ["flock 9 true", "flock -x 9 true", "flock 9 -c true"])
def test_a_numeric_flock_operand_before_a_command_is_a_file(
    marked_repo: Path, command: str
) -> None:
    # P9: flock 9 true creates the file 9 (orchestrator probe, run 20261107-145205).
    hook_input = _cred("Explore", "Bash", str(marked_repo), command=command)
    assert_denied(hook_input, "read-only while")
    assert "Refused: " in str(jail.decide(hook_input, CFG).reason)


@pytest.mark.parametrize(
    ("row", "kind", "form"), S3C_HUNT, ids=[f"{r[0]}-{r[1]}" for r in S3C_HUNT]
)
def test_a_hunt_form_beside_a_coder_table_row_is_refused(row: str, kind: str, form: str) -> None:
    # 228 S3c, shell-semantics pack: each class against each coder row S3c added stays refused.
    command = form.format(wt=WT, repo=CWD, conf=shell.CONFINE_PATH)
    assert_denied(_b("coder", command))


@pytest.mark.parametrize(
    ("row", "kind", "form"), S3C_HUNT_DECLARED, ids=[f"{r[0]}-{r[1]}" for r in S3C_HUNT_DECLARED]
)
def test_a_hunt_form_beside_a_declared_or_install_row_is_refused(
    row: str, kind: str, form: str, tmp_path: Path
) -> None:
    # 228 S3c: the manifest declares the command and enables every install ecosystem.
    doc = {
        "commands": {"unit_test": "bash scripts/test.sh"},
        "packages": {"allowed_installers": ["npm", "python", "cargo", "go"]},
    }
    repo, wt = _narrowed_repo(tmp_path, json.dumps(doc))
    assert decide(_cwd(_b("coder", "bash scripts/test.sh"), repo), CFG).allow
    assert decide(_cwd(_b("coder", "npm ci --ignore-scripts"), repo), CFG).allow
    assert_denied(_cwd(_b("coder", form.format(wt=wt, repo=repo)), repo))


def _claims(form: str) -> str:
    return form.format(claims=SCRIPTS_DIR / "daedalus_claims.py", wt=WT)


@pytest.mark.parametrize("form", CLAIMS_ADMITTED)
def test_the_verifier_claims_call_is_admitted_in_its_one_form(form: str) -> None:
    # 0230: the verifier's claims printer, three options once each in order.
    decision = decide(_b("verifier", _claims(form)), CFG)
    assert decision.allow and not decision.warn, decision.reason


@pytest.mark.parametrize("form", CLAIMS_REFUSED)
def test_the_claims_call_one_token_off_its_form_is_refused(form: str) -> None:
    # 0230: a write-shaped option, a moved option or an off-table value refuses the verifier.
    assert_denied(_b("verifier", _claims(form)))
    # 0230: the read check's own row refuses it too, not only the tripwires before it.
    flags = ("--git", "read-only", "--test-runner", "unit")
    assert evaluate("read_only_bash", _b("verifier", _claims(form)), *flags) is not None


@pytest.mark.parametrize("agent", ["coder", "auditor", "comparer", "orchestrator"])
def test_the_claims_call_is_the_verifier_s_alone(agent: str) -> None:
    assert_denied(_b(agent, _claims(CLAIMS_ADMITTED[0])))


def _log_record(agent: str, command: str) -> tuple[set[str], list[str]]:
    got = jail._admission(command, agent, WT)[1]
    assert jail._passed(got), (agent, command, got)
    done = got.commands[-1]
    return {t.text for t in done.texts}, [p.text for p in done.pathspecs]


@pytest.mark.parametrize("agent", ["main", "coder", "auditor"])
@pytest.mark.parametrize("form", GIT_LOG_COUNT_266)
def test_a_git_log_count_is_text_and_the_path_after_it_a_pathspec(agent: str, form: str) -> None:
    # 266: -n and --max-count, joined or apart, take their value; only the -- word is a pathspec.
    texts, specs = _log_record(agent, form.format(path="src/a.py"))
    assert "3" in texts and specs == ["src/a.py"], (form, texts, specs)
    # 266: the pathspec slot is still judged, so a .env after the count is refused and named.
    assert_denied(_b("coder", form.format(path=".env")), "is a .env file")


@pytest.mark.parametrize("agent", ["main", "coder", "auditor"])
@pytest.mark.parametrize("form", GIT_LOG_COUNT_VALUE_266)
def test_a_word_in_the_git_log_count_slot_is_never_a_pathspec(agent: str, form: str) -> None:
    # 266: git reads that word as the count and rejects a path; the typed record agrees.
    texts, specs = _log_record(agent, form.format(path=".env"))
    assert ".env" in texts and specs == [], (form, texts, specs)


@pytest.mark.parametrize("agent", ["main", "coder", "auditor"])
@pytest.mark.parametrize("form", GIT_LOG_SEARCH_269)
def test_a_git_log_search_value_is_text_and_the_path_after_it_a_pathspec(
    agent: str, form: str
) -> None:
    # 269: -S, -G and --grep take the next word as their value; only the -- word is a pathspec.
    texts, specs = _log_record(agent, form.format(path="src/a.py"))
    assert "token" in texts and specs == ["src/a.py"], (form, texts, specs)
    assert_denied(_b("coder", form.format(path=".env")), "is a .env file")


@pytest.mark.parametrize("agent", ["main", "coder", "auditor"])
@pytest.mark.parametrize("form", GIT_LOG_SEARCH_VALUE_269)
def test_a_word_in_the_git_log_search_slot_is_never_a_pathspec(agent: str, form: str) -> None:
    # 269: git searches for that word; the typed record and the tracked check's table agree.
    texts, specs = _log_record(agent, form.format(path=".env"))
    assert ".env" in texts and specs == [], (form, texts, specs)
    flag = form.split()[2]
    assert flag in jail._GIT_VALUED["log"], flag


@pytest.mark.parametrize(("cls", "agent", "form", "constant"), REFUSED_FIELDS_HUNT_269)
def test_a_refused_fields_hunt_form_names_its_class(
    cls: str, agent: str, form: str, constant: str | None
) -> None:
    # 269 hunt: each check names its class from the typed Refusal, never the refused words.
    if constant is None:
        assert decide(_b(agent, form), CFG).allow, cls
        return
    want = str(getattr(jail, constant, None) or getattr(shell, constant))
    assert_denied(_b(agent, form))
    # 269: the check that owns the class names it, wherever it sits in the agent's chain.
    reasons = [evaluate(script, _b(agent, form), *flags) for script, flags in CHAINS[agent]]
    assert any(want in str(r) for r in reasons if r), (cls, reasons)


@pytest.mark.parametrize(("cls", "args", "missing"), LEDGER_CODES_0247)
def test_a_ledger_append_takes_both_codes_or_neither(
    cls: str, args: str, missing: str | None
) -> None:
    # 0247: a plain-number file's append carries no codes; one code alone names the other.
    command = f"python3 {SCRIPTS_DIR / 'append_ledger.py'} {args}"
    got = decide(_b("charter-docs", command), CFG)
    if missing is None:
        assert got.allow, cls
        return
    assert_denied(_b("charter-docs", command))
    assert got.reason is not None and jail.R_LEDGER_ARGS in got.reason, (cls, got.reason)
    assert f"alone is missing {missing}" in got.reason, cls


# 267: the readers whose git grammar admits content reads; each meets the credential check first.
TRACKED_READERS = ("coder", "auditor", "verifier")
TRACKED_MARKERS = (TRACKED_SECRET_267, TRACKED_UNKNOWN_267, "is a .env file")


@pytest.fixture(scope="module")
def checkouts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return tracked_checkouts(tmp_path_factory.mktemp("tracked").resolve())


def _not_by_credential(agent: str, command: str, repo: Path) -> None:
    deny = first_deny(_cred(agent, "Bash", str(repo), command=command), CFG)
    assert deny is None or deny[0] != "credential_paths", (agent, command, deny)


@pytest.mark.parametrize("agent", TRACKED_READERS)
@pytest.mark.parametrize("command", TRACKED_JUDGED_267)
def test_a_content_read_over_a_tracked_secret_is_denied(
    checkouts: dict[str, Path], agent: str, command: str
) -> None:
    # 267, 0239: the read names the tracked path, or the agent's grammar refuses the form.
    assert_denied(_cred(agent, "Bash", str(checkouts["secret"]), command=command), *TRACKED_MARKERS)
    for kind in ("none", "example"):
        _not_by_credential(agent, command, checkouts[kind])


@pytest.mark.parametrize("agent", TRACKED_READERS)
@pytest.mark.parametrize("command", TRACKED_KEPT_267)
def test_a_read_naming_no_tracked_secret_is_not_a_credential_deny(
    checkouts: dict[str, Path], agent: str, command: str
) -> None:
    _not_by_credential(agent, command, checkouts["secret"])


@pytest.mark.parametrize("agent", TRACKED_READERS)
@pytest.mark.parametrize(("klass", "checkout", "command", "outcome"), TRACKED_HUNT_267)
def test_a_tracked_secret_hunt_form_is_denied_or_a_named_gap(
    checkouts: dict[str, Path], agent: str, klass: str, checkout: str, command: str, outcome: str
) -> None:
    # 267: kept and gap rows pass the credential check; gap rows are the index's blind spots.
    repo = checkouts[checkout]
    if outcome in ("kept", "gap"):
        _not_by_credential(agent, command, repo)
    else:
        assert_denied(_cred(agent, "Bash", str(repo), command=command), *TRACKED_MARKERS)


def _denied_by_grammar(agent: str, command: str, repo: Path) -> None:
    # 267: the role refuses the form; main's wider grammar may still type it for the chain.
    assert not jail.admitted(command, agent, str(repo)), (agent, command)
    deny = first_deny(_cred(agent, "Bash", str(repo), command=command), CFG)
    assert deny is not None, (agent, command)


@pytest.mark.parametrize("agent", TRACKED_READERS)
@pytest.mark.parametrize(("klass", "checkout", "command", "agents", "main"), TRACKED_EXCLUDE_267)
def test_an_exclude_rescue_row_is_denied_or_passes_the_credential_check(
    checkouts: dict[str, Path],
    agent: str,
    klass: str,
    checkout: str,
    command: str,
    agents: str,
    main: str,
) -> None:
    # 267 fix 1: only a literal exclude of every reached secret passes; the rest are denied.
    repo = checkouts[checkout]
    if agents == "kept":
        _not_by_credential(agent, command, repo)
    elif agents == "grammar":
        _denied_by_grammar(agent, command, repo)
    else:
        assert_denied(_cred(agent, "Bash", str(repo), command=command), *TRACKED_MARKERS)


@pytest.mark.parametrize("agent", TRACKED_READERS)
@pytest.mark.parametrize(("command", "outcome"), TRACKED_STAT_267)
def test_a_stat_row_beside_a_tracked_secret_meets_its_outcome(
    checkouts: dict[str, Path], agent: str, command: str, outcome: str
) -> None:
    # 267 fix 2: a stat alone passes the credential check; a patch beside it is denied.
    repo = checkouts["secret"]
    if outcome == "kept":
        _not_by_credential(agent, command, repo)
    elif jail.admitted(command, agent, str(repo)):
        assert_denied(_cred(agent, "Bash", str(repo), command=command), *TRACKED_MARKERS)
    else:
        _denied_by_grammar(agent, command, repo)
