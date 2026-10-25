# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: quoted and escaped spellings of refused paths and command words.
from __future__ import annotations

from pathlib import Path

import pytest

from tests.adversarial.corpus import CREDENTIAL, NESTED, READERS, REPLY_KEY, assert_denied
from tests.payloads import _b, _cred
from tests.test_checks_credential_paths import _bash_in, _key_repo

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
    assert_denied(_cred(agent, "Bash", command=template.format(home=cred_home)), CREDENTIAL)


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
