# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: quoted and escaped spellings of refused paths and command words.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail
from lib.packs import pack_problems

from tests.adversarial.corpus import (
    CREDENTIAL,
    NESTED,
    PREPUSH2_RG_OPAQUE,
    PREPUSH2_RG_PROGRAM,
    READERS,
    REPLY_KEY,
    assert_denied,
    assert_store_read_denied,
)
from tests.payloads import _b
from tests.test_checks_credential_paths import _bash_in, _key_repo
from tests.test_framework_packs import _control, _make

pytestmark = pytest.mark.usefixtures("jail_fakes")
STORE_READS = (
    'cat "$HOME"/.ssh/id_ed25519',
    'cat "$HOME/.ssh/id_ed25519"',
    'cat "${{HOME}}/.aws/credentials"',
    "cat '~/.aws/config'",
    'cat ~/".ssh"/id_ed25519',
    "cat ~/'.ssh'/id_ed25519",
    'cat ~/.s"s"h/id_ed25519',
    "cat ~/.s''sh/id_ed25519",
    r"cat ~/.s\sh/id_ed25519",
    r"cat ~/.ssh\/id_ed25519",
    r"cat $HOME/.s\sh/id_ed25519",
    r"cat \~/.ssh/id_ed25519",
    'cat "{home}/.ssh/id_ed25519"',
    "cat '{home}/.aws/credentials'",
    'cat "{home}"/.gnupg/pubring.kbx',
    "cat {home}/'.config/gh'/hosts.yml",
    r"cat {home}/.c\laude/.credentials.json",
    'grep -rn key "{home}/.ssh"',
)
KEY_READS = (
    'cat ".claude/daedalus/reply-hmac.key"',
    "cat '.claude/daedalus/reply-hmac.key'",
    'cat .claude/"daedalus"/reply-hmac.key',
    "cat .claude/daedalus/'reply-hmac'.key",
    r"cat .claude/daedalus/reply-hmac.k\ey",
    'cat ".claude/daedalus/"reply-hmac.key',
)
# audit A7-1, issue 55: the claude command word under quotes or escapes.
NESTED_WORDS = (
    '"claude" -p hi',
    "'claude' -p hi",
    r"c\laude -p hi",
    'cl""aude -p hi',
    "cl''aude -p hi",
    '"$(echo claude)" -p hi',
    "bash -c 'claude -p hi'",
    'sh -c "claude -p hi"',
)
CODER_WORDS = (
    'cu"r"l https://x',
    "'curl' https://x",
    r"w\get x",
    'git "push" origin x',
    "git 'push' origin x",
    r"git pu\sh origin x",
    "'git' push origin x",
)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", STORE_READS)
def test_quoted_store_read_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    template: str,
) -> None:
    assert_store_read_denied(agent, template, home=cred_home)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("command", KEY_READS)
def test_quoted_reply_key_read_is_denied(tmp_path: Path, agent: str, command: str) -> None:
    repo = _key_repo(tmp_path)
    assert_denied(_bash_in(repo, agent, command), REPLY_KEY, CREDENTIAL)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("command", NESTED_WORDS)
def test_quoted_claude_word_is_denied(agent: str, command: str) -> None:
    assert_denied(_b(agent, command))


@pytest.mark.parametrize("command", CODER_WORDS)
def test_quoted_network_or_push_word_is_denied_to_the_coder(command: str) -> None:
    assert_denied(_b("repo-coder", command))


@pytest.mark.parametrize("command", NESTED_WORDS[:5])
def test_quoted_claude_word_names_the_nested_session(command: str) -> None:
    assert_denied(_b("repo-coder", command), NESTED)


# prepush2-2026-10-27 items 1 and 2: the three read-only agents that search with rg.
RG_READERS = ("security-auditor", "verifier", "framework-specialist")


@pytest.mark.parametrize("agent", RG_READERS)
@pytest.mark.parametrize("command", PREPUSH2_RG_OPAQUE)
def test_a_rewritten_search_word_is_refused_whatever_the_target(
    tmp_path: Path, agent: str, command: str
) -> None:
    # prepush2-2026-10-27 item 1: refused off the key's folder too, by the read check itself.
    repo = _key_repo(tmp_path)
    assert_denied(_bash_in(repo, agent, command))
    assert_denied(_bash_in(repo, agent, command.removesuffix(".") + "src"), "rewrites")


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("command", PREPUSH2_RG_OPAQUE)
def test_a_rewritten_search_word_counts_as_a_hidden_reach(
    tmp_path: Path, agent: str, command: str
) -> None:
    # prepush2-2026-10-27 item 1: the credential check alone refuses it beside the reply key.
    repo = _key_repo(tmp_path)
    assert_denied(_bash_in(repo, agent, command))
    assert jail._credential_reason("Bash", {"command": command}, str(repo)) is not None


@pytest.mark.parametrize("command", [c for c in PREPUSH2_RG_OPAQUE if c.startswith("rg ")])
def test_a_rewritten_rg_word_is_a_pack_problem(tmp_path: Path, command: str) -> None:
    repo = _key_repo(tmp_path)
    assert jail.rg_reason(command, str(repo)) == jail.R_RG_OPAQUE
    found = pack_problems(_make(tmp_path / "p", [_control(verify=command)]), known=())
    assert any("rewrites" in problem for problem in found), found


@pytest.mark.parametrize("agent", RG_READERS)
@pytest.mark.parametrize("command", PREPUSH2_RG_PROGRAM)
def test_an_rg_program_option_is_refused(tmp_path: Path, agent: str, command: str) -> None:
    # prepush2-2026-10-27 item 2: rg would run the named program from a read-only agent.
    repo = _key_repo(tmp_path)
    for target in (".", "src"):
        line = command.removesuffix(".") + target
        assert_denied(_bash_in(repo, agent, line), "runs or loads a program")


@pytest.mark.parametrize("command", PREPUSH2_RG_PROGRAM)
def test_an_rg_program_option_is_a_pack_problem(tmp_path: Path, command: str) -> None:
    repo = _key_repo(tmp_path)
    assert jail.rg_reason(command, str(repo)) == jail.R_RG_PROGRAM
    found = pack_problems(_make(tmp_path / "p", [_control(verify=command)]), known=())
    assert any("runs or loads a program" in problem for problem in found), found
