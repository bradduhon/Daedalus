# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: brace and glob spellings that reach a credential store or the reply key.
from __future__ import annotations

from pathlib import Path

import pytest

from tests.adversarial.corpus import (
    CREDENTIAL,
    READERS,
    REPLY_KEY,
    assert_denied,
    assert_store_read_denied,
)
from tests.payloads import _cred
from tests.test_checks_credential_paths import (
    BRACE_CLASS_TABLE,
    RE_ROOTED_READS,
    SEQUENCE_READS,
    _bash_in,
    _key_repo,
)

pytestmark = pytest.mark.usefixtures("jail_fakes")
# issue 53, audit B4 rounds 1 to 3: the existing refused rows, plus the follow-up spellings.
STORE_READS = (
    *SEQUENCE_READS,
    *RE_ROOTED_READS,
    *(template for _, template, refused in BRACE_CLASS_TABLE if refused),
    "grep -rn key {home}/{{.ssh,x}}",
    "cat {home}/{{x,.aws}}/config",
    "cat ~/.{{ssh,aws}}/x",
    "cat ~/.ss*/id_ed25519",
    "cat ~/.ss?/id_ed25519",
    "cat ~/.[s]sh/id_ed25519",
    "cat ~/*/id_ed25519(D)",
    "setopt GLOB_DOTS && cat ~/*/id_ed25519",
    "setopt globdots; cat {home}/*/credentials",
    "shopt -s dotglob && cat {home}/*/credentials",
    "cat {home}/**/credentials",
    "cat ~/**/id_ed25519",
    "cat {home}/.{{s..s}}sh/{{id_ed25519,x}}",
    "cat {{{home}/x,{home}/.aws/credentials}}",
    "grep -rn key {home}/.{{a..z}}ws",
)
GLOB_TOOL = (
    "{home}/.{{s..s}}sh/*",
    "~/.{{a..z}}ws/credentials",
    "{{{home}/.ssh,x}}/*",
    "{{{home}/.aws/credentials,x}}",
    "{{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,{home}/.ssh}}/*",
    "{{x,{home}/.s{{s..s}}h}}/*",
    "{home}/.ss?/*",
    "~/.[s]sh/*",
)
# 20261018-234006 round 5: root-anchored globs; the shell and the Grep tool alike.
KEY_GREP_GLOBS = (
    "**/reply-hmac.key",
    "*.key",
    ".claude/**",
    "*.{key,md}",
    "/.claude/daedalus/reply-hmac.key",
    "/.claude/**",
    "{reply-hmac.key,x}",
    "{reply-hmac.key}",
    "reply-hmac.{k..k}ey",
    "/**/reply-hmac.key",
)
KEY_READS = (
    "cat .claude/daedalus/reply-hmac.ke*",
    "cat .claude/daedalus/*",
    "cat .claude/daedalus/reply-hmac.{{key,x}}",
    "cat .claude/daedalus/{{reply-hmac.key,x}}",
    "cat .claude/daedalus/reply-hmac.{{k..k}}ey",
    "cat .claude/{{daedalus,x}}/reply-hmac.key",
    "cat .claude/daedalus/reply-hmac.ke?",
    "cat .claude/daedalus/reply-hmac.[k]ey",
    "cat .claude/*/reply-hmac.key",
    "cat .claude/**/reply-hmac.key",
    "cat {repo}/.claude/daedalus/reply-hmac.{{key,x}}",
    "grep -ra . .claude/daedalus",
    "grep -r token .claude",
    "rg -uu token .claude",
    "rg --hidden -g '/.claude/**' token",
    "rg -uu --glob=/.claude/daedalus/reply-hmac.key .",
)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", STORE_READS)
def test_bash_brace_or_glob_into_a_store_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    template: str,
) -> None:
    assert_store_read_denied(agent, template, home=cred_home)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", GLOB_TOOL)
def test_glob_tool_brace_into_a_store_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    template: str,
) -> None:
    pattern = template.format(home=cred_home)
    assert_denied(_cred(agent, "Glob", pattern=pattern), CREDENTIAL, "does not expand")


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("glob", KEY_GREP_GLOBS)
def test_grep_tool_glob_reaching_the_reply_key_is_denied(
    tmp_path: Path, agent: str, glob: str
) -> None:
    repo = _key_repo(tmp_path)
    for path in (None, str(repo)):
        tool_input = {"pattern": ".", "glob": glob} | ({"path": path} if path else {})
        assert_denied(_cred(agent, "Grep", cwd=str(repo), **tool_input), REPLY_KEY, CREDENTIAL)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", KEY_READS)
def test_bash_brace_or_glob_reaching_the_reply_key_is_denied(
    tmp_path: Path, agent: str, template: str
) -> None:
    repo = _key_repo(tmp_path)
    assert_denied(_bash_in(repo, agent, template.format(repo=repo)), REPLY_KEY, CREDENTIAL)
