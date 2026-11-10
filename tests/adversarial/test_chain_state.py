# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 121, 228 S4: the excluded roots check reads the Admitted record; an icase export, a body,
# a magic pathspec and a built word are each a shape off the agent's table, refused at its span.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail

from tests.adversarial.corpus import (
    A3_ADMITTED,
    A3_ISSUE_121_ADMITTED,
    A3_ISSUE_121_REFUSED,
    A3_RULE_ROWS,
    CODER_REFUSED,
    S4_BUILT_OPERAND,
    S4_BUILT_OPTION,
    S4_HUNT,
    S4_ISSUE_ROWS,
    S4_MAIN_TYPED_PASS,
    S4_PARAM_IN_PATHSPEC,
    S4_PARAM_IN_PATHSPEC_REFUSAL,
    S4_TYPED_PASS_225,
    assert_denied,
)
from tests.conftest import CFG, WT, write_train_marker
from tests.payloads import _cred
from tests.test_excluded_roots import _config, _payload, _roots, repo  # noqa: F401

ICASE = jail.R_EXCLUDED_ICASE.split("{spec}")[0]
UNSEEN = jail.R_EXCLUDED_UNSEEN.split("{source}")[0]
# issue 121: (root, command, outcome); the issue's rows name Private, the corpus rows NOTES.
OUTCOMES = (
    *(("private", c, "pass") for c in A3_ISSUE_121_ADMITTED),
    *(("private", c, "refuse") for c in A3_ISSUE_121_REFUSED),
    *(("notes", c, "pass") for c in A3_ADMITTED),
)


def _reason(command: str, cwd: Path, root: str, agent: str = "main") -> str | None:
    got = jail._admission(command, agent, str(cwd))[1]
    return jail.excluded_root_reason(got, str(cwd), _roots(str(cwd / root)))


def test_each_rule_has_a_refused_row_in_the_git_family() -> None:
    # spec: one refused row per owned rule per command family; git is this unit's one family.
    assert {rule for rule, _ in A3_RULE_ROWS} == {"P10", "P11"}


@pytest.mark.parametrize(("rule", "form"), A3_RULE_ROWS)
def test_a_chain_state_row_is_refused(
    repo: Path,  # noqa: F811
    jail_fakes: None,
    rule: str,
    form: str,
) -> None:
    # P10, P11, 228 S4: the coder's grammar refuses the row at its span; the 225 rows it admits
    # pass the typed reader and git_grammar refuses their newline. Main's admitted rows meet the
    # typed reader, and its refused rows warn during a train.
    coder = _cred("coder", "Bash", WT, command=form)
    if form in S4_TYPED_PASS_225:
        assert_denied(coder)
        assert _reason(form, repo, "notes", "coder") is None, form
    elif form in S4_PARAM_IN_PATHSPEC:
        assert_denied(coder, S4_PARAM_IN_PATHSPEC_REFUSAL)
    else:
        assert_denied(coder, CODER_REFUSED)
    got = _reason(form, repo, "notes")
    if jail.admitted(form, "main", str(repo)):
        want = form in S4_MAIN_TYPED_PASS
        assert (got is None) if want else str(got).startswith((ICASE, UNSEEN)), (form, got)
        return
    assert got is None, (form, got)
    write_train_marker(repo)
    warned = jail.decide(_payload("main", repo, form), _config(repo))
    assert warned.warn and "Refused: " in str(warned.reason), (form, warned.reason)


@pytest.mark.parametrize(("root", "command", "outcome"), OUTCOMES)
def test_the_issue_rows_and_the_admitted_forms(
    repo: Path,  # noqa: F811
    root: str,
    command: str,
    outcome: str,
) -> None:
    # issue 121, 228 S4: reads and messages pass; an export before git add refuses on the typed
    # record; a prefix on git add is off main's table, so only its folder is judged.
    got = _reason(command, repo, root)
    if outcome == "pass":
        assert got is None, (command, got)
    elif jail.admitted(command, "main", str(repo)):
        assert str(got).startswith(ICASE), (command, got)
    else:
        assert got is None, (command, got)


@pytest.mark.parametrize(("issue", "agent", "form", "reason"), S4_ISSUE_ROWS)
def test_an_issue_row_is_unadmitted_and_its_refusal_names_why(
    issue: str, agent: str, form: str, reason: str
) -> None:
    # 228 S4: issues 223, 225, 226, 230 and 231 close on these rows; each names its word.
    command = form.replace("{wt}", WT)
    refused = jail._refused(jail._admission(command, agent, WT)[1])
    assert refused is not None and refused.reason == reason, (issue, command, refused)
    assert refused.text and refused.text in command, (issue, refused)
    if agent not in ("main", "foreign"):
        assert_denied(_cred(agent, "Bash", WT, command=command))


def test_a_225_message_passes_the_typed_reader(
    repo: Path,  # noqa: F811
) -> None:
    # 225: a -m value is text, never a pathspec, so its icase spelling and gate word pass; the
    # measurement rows A3-32 and A3-33 run the same forms through a unit worktree's chain.
    for form in ("git commit -m 'fix :(icase) in local env' -- src/a.md", *S4_TYPED_PASS_225):
        assert jail.admitted(form, "coder", str(repo)), form
        assert _reason(form, repo, "notes", "coder") is None, form


def test_231_stays_open_outside_a_marked_repo(
    marked_repo: Path,
    other_repo: Path,
) -> None:
    # 0224, 231: unadmitted, yet from an unmarked folder it runs; the cross-repo case is 231's.
    assert marked_repo.is_dir()
    command = "sh -c 'touch \"$(cat p)/x\"'"
    hook_input = _cred("general-purpose", "Bash", str(other_repo), command=command)
    assert jail.decide(hook_input, CFG).allow
    assert not jail.admitted(command, "foreign", str(other_repo))


@pytest.mark.parametrize(("agent", "form"), S4_BUILT_OPTION)
def test_a_built_option_is_refused_or_typed_opaque(
    repo: Path,  # noqa: F811
    agent: str,
    form: str,
) -> None:
    # 257: an agent's grammar refuses the built option at its span; main's types it opaque and
    # the reader refuses the git call while a root is declared, never reading it as an option.
    got = jail._admission(form, agent, str(repo))[1]
    refused = jail._refused(got)
    if agent != "main":
        assert refused is not None and refused.text in form and "$" in refused.text, refused
        return
    if refused is not None:
        assert "$" in refused.text, refused
        return
    assert any(o.glob for c in got.commands for o in c.options), form
    assert str(_reason(form, repo, "notes")).startswith(UNSEEN), form


@pytest.mark.parametrize(("agent", "form", "raw"), S4_BUILT_OPERAND)
def test_an_operand_after_a_built_option_is_typed_unknown(
    repo: Path,  # noqa: F811
    agent: str,
    form: str,
    raw: str,
) -> None:
    # 257: the pathspec slot keeps the operand with the unknown mark; the reader fails closed.
    got = jail._admission(form, agent, str(repo))[1]
    assert jail._refused(got) is None, form
    specs = [(p.text, p.glob) for c in got.commands for p in c.pathspecs]
    assert specs == [(raw, True)], specs
    assert str(_reason(form, repo, "notes")).startswith(UNSEEN), form


@pytest.mark.parametrize(("klass", "agent", "form"), S4_HUNT)
def test_a_hunt_form_is_refused_on_its_typed_record(
    repo: Path,  # noqa: F811
    klass: str,
    agent: str,
    form: str,
) -> None:
    # 228 S4 hunt: each hiding form against a declared root, read from the Admitted record.
    command = form.replace("{wt}", str(repo))
    assert jail.admitted(command, agent, str(repo)), (klass, command)
    got = _reason(command, repo, "notes", agent)
    assert got is not None and ("excluded root" in got or got.startswith((ICASE, UNSEEN))), got
