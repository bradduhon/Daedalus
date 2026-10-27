# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: brace and glob spellings that reach a credential store or the reply key.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail
from lib.credential_paths import glob_reaches

from tests.adversarial.corpus import (
    CREDENTIAL,
    FIX1_GREP_GLOBS,
    FIX1_RG_GLOBS,
    FIX1_RG_GLOBS_ALLOWED,
    READERS,
    REPLY_KEY,
    assert_denied,
    assert_store_read_denied,
)
from tests.conftest import CFG
from tests.hook_chain import decide
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


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("command", FIX1_RG_GLOBS)
def test_an_rg_whitelist_glob_reaching_the_reply_key_is_denied(
    tmp_path: Path, agent: str, command: str
) -> None:
    # SC-12: a -g, --glob or --iglob whitelist overrides rg's hidden-folder skip.
    assert_denied(_bash_in(_key_repo(tmp_path), agent, command), REPLY_KEY, CREDENTIAL)


@pytest.mark.parametrize("command", FIX1_RG_GLOBS_ALLOWED)
def test_an_rg_glob_naming_no_hidden_folder_still_passes(tmp_path: Path, command: str) -> None:
    # SC-12: the shipped pack verify globs (*.tf, *.yml) stay admitted beside a reply key.
    d = decide(_bash_in(_key_repo(tmp_path), "framework-specialist", command), CFG)
    assert d.allow, (command, d.reason)


def test_an_rg_whitelist_glob_reaching_a_credential_store_is_denied(
    cred_home: Path,  # noqa: F811
) -> None:
    # SC-12: the same override reaches a hidden credential store under home.
    (cred_home / ".ssh").mkdir()
    forms = ("rg -g .ssh -g 'id_*' BEGIN ~", "rg --iglob=.SSH BEGIN {home}")
    forms += ("rg -g '**/.ssh' -g '**/.ssh/**' BEGIN ~", "rg -g '.ssh/' BEGIN {home}")
    forms += ("rg -g '\\.ssh' -g '\\.ssh/**' BEGIN {home}",)
    for command in forms:
        assert_store_read_denied("security-auditor", command, home=cred_home)
    assert jail._rg_globs(["-e", "-g", "-g", "!x", "--glob", "$X", "-ng*.tf"]) == ["*", "*.tf"]
    assert jail._rg_globs(["-g=.claude"]) == ["=.claude", ".claude"]
    # SC-12: outside the modelled characters a glob reaches every store; a negated glob never does.
    assert glob_reaches(["\\.x"], ["a"]) and glob_reaches(["[a]"], ["b"])
    assert not glob_reaches(["!\\.ssh", "**/*.py", "*Dockerfile*"], [".ssh"])


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("glob", FIX1_GREP_GLOBS)
def test_grep_tool_gitignore_glob_reaching_the_reply_key_is_denied(
    tmp_path: Path, agent: str, glob: str
) -> None:
    # SC-12: the Grep tool shares glob_reaches, so a zero-folder **/ reaches the key too.
    repo = _key_repo(tmp_path)
    tool_input = {"pattern": ".", "glob": glob, "path": str(repo)}
    assert_denied(_cred(agent, "Grep", cwd=str(repo), **tool_input), REPLY_KEY, CREDENTIAL)


def test_grep_tool_pack_globs_still_pass(tmp_path: Path) -> None:
    # SC-12: globs naming no hidden folder or key stay admitted for the Grep tool.
    repo = _key_repo(tmp_path)
    for glob in ("*.tf", "**/*.py", "*Dockerfile*", "src/**"):
        tool_input = {"pattern": ".", "glob": glob, "path": str(repo)}
        d = decide(_cred("framework-specialist", "Grep", cwd=str(repo), **tool_input), CFG)
        assert d.allow, (glob, d.reason)
