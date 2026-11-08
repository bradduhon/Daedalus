# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 116, 81: a command string handed to a shell or an interpreter is found, walked or refused.
from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from lib import jail, shell

from tests.adversarial.corpus import (
    A2_ADMITTED,
    A2_FIX1_RUN,
    A2_FIX1_UNMARKED,
    A2_FIX2_RUN,
    A2_FIX3_ADMITTED,
    A2_FIX3_RUN,
    A2_FIX3_UNMARKED,
    A2_FIX4_ADMITTED,
    A2_FIX4_RUN,
    A2_FIX4_UNMARKED,
    A2_FIX5_ADMITTED,
    A2_FIX5_OPAQUE,
    A2_FIX5_UNMARKED,
    A2_FIX6_ADMITTED_MARKED,
    A2_ISSUE_81,
    A2_ISSUE_116,
    A2_PROBE,
    A2_PROGRAM_ARGS,
    A2_RULE_ROWS,
    assert_denied,
)
from tests.conftest import CFG
from tests.payloads import _b, _cred

FINDINGS = {"shell": jail.R_SHELL_BODY, "inline": jail.R_INLINE_BODY, "env": shell.R_ENV_SPLIT}
# fix1-a2: a heredoc line's $1 is also judged at the top level, as a credential path.
CREDENTIAL_PARAM = "could be a credential path"
# issue 81: one body form per walked kind; {cmd} is the quoted inner command.
BODY_FORMS = ("bash -c {cmd}", "sh -c {cmd}", "bash <<< {cmd}", "env -S {cmd}")


def _foreign(cwd: Path, command: str) -> dict[str, object]:
    return _cred("Explore", "Bash", str(cwd), command=command)


def _nest(form: str, command: str, levels: int) -> str:
    for _ in range(levels):
        command = form.format(cmd=shlex.quote(command))
    return command


def test_each_rule_has_a_refused_row_in_each_family() -> None:
    # spec: one refused row per owned rule per command family.
    cells = {(rule, family) for rule, family, _, _ in A2_RULE_ROWS}
    rules, families = ("P5", "P6", "P7", "P8"), ("shell", "interpreter", "env")
    assert cells == {(r, f) for r in rules for f in families}


@pytest.mark.parametrize(("rule", "family", "finding", "form"), A2_RULE_ROWS)
def test_a_hidden_body_is_refused_per_rule_and_family(
    marked_repo: Path, rule: str, family: str, finding: str, form: str
) -> None:
    # P5 to P8, 228 S3: the grammar refuses a foreign agent's body while a train runs; the
    # refusal keeps the finding its kind names.
    command = form.format(repo=marked_repo)
    assert not jail.admitted(command, "foreign", str(marked_repo)), (rule, family, command)
    assert_denied(_foreign(marked_repo, command), FINDINGS[finding])


@pytest.mark.parametrize("command", A2_ISSUE_116 + A2_ISSUE_81)
def test_the_issue_reproduction_rows_are_refused(marked_repo: Path, command: str) -> None:
    # issue 116, 81: the rows as the issues relay them, refused while a train runs.
    assert not jail.admitted(command, "foreign", str(marked_repo)), command
    assert_denied(_foreign(marked_repo, command), *FINDINGS.values())


def test_the_probe_rows_now_give_a_finding(marked_repo: Path) -> None:
    # issue 116, 228 S3: the probe gave None for these; each refusal now opens with its finding.
    want = [jail.R_SHELL_BODY] * 3 + [jail.R_INLINE_BODY, shell.R_ENV_SPLIT]
    for command, finding in zip(A2_PROBE, want, strict=True):
        reason = str(jail.decide(_foreign(marked_repo, command), CFG).reason)
        assert reason.startswith(finding), (command, reason)
    assert shell.env_split_values(shlex.split(A2_PROBE[-1])) == ["touch y"]


@pytest.mark.parametrize("levels", (1, 2, 3))
@pytest.mark.parametrize("form", BODY_FORMS)
def test_the_walk_names_a_write_inside_each_body_to_depth_three(
    marked_repo: Path, other_repo: Path, form: str, levels: int
) -> None:
    # issue 81, 228 S3: from an unmarked folder, a path the body names scopes the call.
    command = _nest(form, f"touch {marked_repo}/x", levels)
    assert str(marked_repo / "x") in (jail._scope_paths(command, str(other_repo)) or ())
    assert not jail._past_cap(command, str(other_repo))
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, shell.R_ENV_SPLIT)


@pytest.mark.parametrize("form", BODY_FORMS)
def test_a_body_past_the_depth_cap_is_refused(other_repo: Path, form: str) -> None:
    # issue 81, 228 S3: past _SCOPE_DEPTH nothing is read, so the call fails closed.
    command = _nest(form, f"touch {other_repo}/x", jail._SCOPE_DEPTH + 1)
    assert jail._past_cap(command, str(other_repo))
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, shell.R_ENV_SPLIT)


@pytest.mark.parametrize("command", A2_ADMITTED + A2_PROGRAM_ARGS + A2_FIX3_ADMITTED)
def test_program_arguments_after_the_script_are_no_body(marked_repo: Path, command: str) -> None:
    # A2 spec correction, 228 S3: the words after the script or module are the program's own,
    # so the run is refused as a foreign write, never as a hidden body.
    d = jail.decide(_foreign(marked_repo, command), CFG)
    assert not d.allow and not str(d.reason).startswith(tuple(FINDINGS.values())), command


@pytest.mark.parametrize(("finding", "form"), A2_FIX1_RUN + A2_FIX2_RUN + A2_FIX3_RUN + A2_FIX4_RUN)
def test_a_fix_round_form_is_refused_in_a_run(marked_repo: Path, finding: str, form: str) -> None:
    # fix round 1: fd-prefixed stdin, raw expansions, off-table options, eval and source.
    command = form.format(repo=marked_repo)
    assert not jail.admitted(command, "foreign", str(marked_repo)), command
    assert_denied(_foreign(marked_repo, command), FINDINGS[finding])


@pytest.mark.parametrize(
    "form", A2_FIX1_UNMARKED + A2_FIX3_UNMARKED + A2_FIX4_UNMARKED + A2_FIX5_UNMARKED
)
def test_a_fix_round_form_from_an_unmarked_folder_is_refused(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # fix round 1, issue 81, 228 S3: the text names {repo}, so the call is scoped and refused.
    command = form.format(repo=marked_repo)
    paths = jail._scope_paths(command, str(other_repo)) or ()
    assert any(p == str(marked_repo) or p.startswith(f"{marked_repo}/") for p in paths), command
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, CREDENTIAL_PARAM)


@pytest.mark.parametrize("form", A2_FIX5_OPAQUE)
def test_a_run_body_writing_through_an_unresolved_word_names_every_piece(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # fix1-a2 (R1 to R3), 228 S3: every literal piece of the text is a target, so a marked
    # repository the command names refuses it from an unmarked folder.
    command = form.format(repo=marked_repo)
    paths = jail._scope_paths(command, str(other_repo)) or ()
    assert any(p == str(marked_repo) or p.startswith(f"{marked_repo}/") for p in paths), command
    assert not jail._past_cap(command, str(other_repo))
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY, CREDENTIAL_PARAM)


@pytest.mark.parametrize("command", A2_FIX5_ADMITTED)
def test_an_unresolved_body_write_with_no_train_anywhere_is_admitted(
    other_repo: Path, command: str
) -> None:
    # fix1-a2 (0035): with no train marker on this machine, foreign agents and main act as on
    # the audited tip 1ba48d0.
    assert not jail._past_cap(command, str(other_repo)), command
    assert jail.decide(_foreign(other_repo, command), CFG).allow, command
    assert jail.decide(_b(None, command), CFG).allow, command


@pytest.mark.parametrize("form", [f for f in A2_FIX6_ADMITTED_MARKED if "{repo}" not in f])
def test_a_body_that_writes_only_outside_a_marked_repo_is_admitted(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # fix1-a2 (R1, R2): set -o values and substitutions off the write positions bind nothing.
    command = form.format(repo=marked_repo)
    decision = jail.decide(_foreign(other_repo, command), CFG)
    assert decision.allow, (command, decision.reason)


@pytest.mark.parametrize("form", [f for f in A2_FIX6_ADMITTED_MARKED if "{repo}" in f])
def test_a_body_naming_a_marked_repo_is_a_table_gap(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    # 228 S3 table gap: a body is unadmitted, so a marked repo its text names scopes the call,
    # read or write; the deleted walker admitted these reads.
    command = form.format(repo=marked_repo)
    assert_denied(_foreign(other_repo, command), jail.R_SHELL_BODY)


@pytest.mark.parametrize("command", A2_FIX4_ADMITTED)
def test_a_here_string_read_by_a_plain_command_is_admitted(
    marked_repo: Path, other_repo: Path, command: str
) -> None:
    # fix round 4, design A: the here-string names no repo, and no shell reads the stream.
    assert str(marked_repo) not in " ".join(jail._scope_paths(command, str(other_repo)) or ())
    assert jail.decide(_foreign(other_repo, command), CFG).allow, command
    assert jail.decide(_b(None, command), CFG).allow, command


@pytest.mark.parametrize("command", A2_ADMITTED + A2_FIX3_ADMITTED)
def test_a_module_or_script_run_is_no_body(other_repo: Path, command: str) -> None:
    # P7, 228 S3: python3 -m <module> and python3 <script path> are plain segments.
    assert jail._plain_segments(command) == [shlex.split(command)]
    assert jail.decide(_foreign(other_repo, command), CFG).allow
    assert jail.decide(_b(None, command), CFG).allow


# 228 S3 hunt (coder file list): each hiding form writes {repo}/x from an unmarked folder; the
# parse names the repo, so the call is scoped and the grammar refuses it, naming what it refused.
HUNT_SCOPE = (
    "touch -- {repo}/x",
    "cp -t {repo} /etc/hosts",
    "rm -- {repo}/x",
    "tee - {repo}/x",
    "cp -rt {repo} /etc",
    "cp --target-dir={repo} /etc/hosts",
    "/usr/bin/touch {repo}/x",
    "python3.12 -c \"open('{repo}/x', 'w')\"",
    "nice timeout 5 touch {repo}/x",
    "LC_ALL=C touch {repo}/x",
    "export D={repo}; touch $D/x",
    "declare -x D={repo}; touch $D/x",
    "set -a; D={repo}; touch $D/x",
    "D={parent}; touch $D/marked/x",
    "D={parent}; cd $D/marked; touch x",
    "( touch {repo}/x )",
    "{{ touch {repo}/x; }}",
    "echo x | tee {repo}/x",
    "tee {repo}/x <<< hi",
    "cat > {repo}/x <<'E'\nhi\nE",
    "cat > {repo}/x <<E\nhi\nE",
    "> {repo}/x echo hi",
    ">{repo}/x cat /etc/hosts",
    "touch {repo}/`date`",
    "touch {repo}/*",
    "touch $'{repo}/x'",
    "touch {{{repo},/tmp/q}}/x",
    "env -C {repo} touch x",
    "git -C {repo} commit -m x",
    "sh -c 'cd {parent} && touch marked/x'",
    "sh -c 'touch \"$9\"' _ /tmp /usr /etc /var /opt /home /bin /srv {repo}/x",
)


@pytest.mark.parametrize("form", HUNT_SCOPE)
def test_a_hunt_form_writing_into_a_marked_repo_is_scoped_and_named(
    marked_repo: Path, other_repo: Path, form: str
) -> None:
    command = form.format(repo=marked_repo, parent=marked_repo.parent)
    d = jail.decide(_foreign(other_repo, command), CFG)
    assert not d.allow and "Refused: " in str(d.reason), (command, d.reason)
