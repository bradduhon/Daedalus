# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: $HOME, ~ and ${VAR} spellings that reach a store or leave the unit worktree.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import shell

from tests.adversarial.corpus import (
    A3_APPEND_ENV,
    CREDENTIAL,
    OUTSIDE,
    READERS,
    assert_denied,
    assert_store_read_denied,
)
from tests.conftest import CFG, WT
from tests.hook_chain import decide
from tests.payloads import _b, _cred

pytestmark = pytest.mark.usefixtures("jail_fakes")
STORE_READS = (
    "cat ~/.ssh/id_ed25519",
    "cat $HOME/.aws/credentials",
    "cat ${{HOME}}/.gnupg/pubring.kbx",
    "cat ${{HOME:-x}}/.ssh/id",
    "cat ${{HOME%/}}/.ssh/id",
    "cat ${{HOME:+$HOME}}/.aws/config",
    "D=~/.ss; cat ${{D}}h/id",
    "D=~/.ss; cat $D''h/id",
    "D=$HOME; cat $D/.ssh/id",
    "cat ${{UNSET_THING}}/id",
    "cat $DAEDALUS_UNSET_PROBE/.ssh/id",
    "cd ~ && cat .ssh/id_ed25519",
    "cd && cat .aws/credentials",
    "cd $HOME && cat .ssh/id_ed25519",
    "cd ${{HOME}} && cat .aws/credentials",
    "cd ~/.ssh && cat id_ed25519",
    "cd ~; cat .config/gh/hosts.yml",
    "pushd ~ && cat .ssh/id_ed25519",
    "ls ~/.config/gh",
    "head -c 10 ~/.claude/.credentials.json",
    "cp --target-directory=~/.ssh/x a",
    "grep -rn key ~/.aws",
    "grep -R BEGIN ~/.config",
    "rg --hidden BEGIN ~",
    "cat {home}/../{name}/.ssh/id_ed25519",
)
# 20261019-234359 Blocks: the coder writes only inside its unit worktree, never home.
CODER_WRITES = (
    "tee $HOME/.bashrc",
    "tee ~/.profile",
    "tee ${{HOME}}/x.txt",
    "cp {wt}/README.md ~/x.txt",
    "echo x > $HOME/.profile",
    "echo x >> ~/.bashrc",
    "tee $PWD/src/a.py",
    "tee ${{PWD}}/service-manifest.json",
    "tee $OLDPWD/x",
    "tee $TMPDIR/x",
    "cd ~ && tee x.txt",
)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", STORE_READS)
def test_expanded_store_read_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    template: str,
) -> None:
    assert_store_read_denied(agent, template, home=cred_home, name=cred_home.name)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("path", ("~/.ssh/id_ed25519", "~/.aws/credentials", "~/.gnupg"))
def test_tilde_in_a_read_tool_path_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    path: str,
) -> None:
    assert_denied(_cred(agent, "Read", file_path=path), CREDENTIAL)
    assert_denied(_cred(agent, "Grep", pattern="key", path=path), CREDENTIAL)


@pytest.mark.parametrize("template", CODER_WRITES)
def test_expanded_coder_write_outside_the_worktree_is_denied(
    cred_home: Path,  # noqa: F811
    template: str,
) -> None:
    assert_denied(_b("coder", template.format(wt=WT)))


@pytest.mark.parametrize("command", A3_APPEND_ENV)
def test_an_appending_or_element_assignment_prefix_is_refused(command: str) -> None:
    # issue 121: NAME+= and NAME[...]= are env assignments, judged as NAME= is.
    assert_denied(_cred("coder", "Bash", WT, command=command), shell.R_ENV)


def test_a_safe_name_appends_as_it_assigns() -> None:
    # issue 121: TZ+= on a safe name passes exactly where TZ= does.
    assign = decide(_cred("coder", "Bash", WT, command="TZ=x python3 -m pytest -q"), CFG)
    append = decide(_cred("coder", "Bash", WT, command="TZ+=x python3 -m pytest -q"), CFG)
    assert assign.allow and append.allow, (assign.reason, append.reason)


@pytest.mark.parametrize("path", ("~/.bashrc", "~/x.txt", "$HOME/x.txt"))
def test_tilde_in_a_coder_write_tool_path_is_denied(
    cred_home: Path,  # noqa: F811
    path: str,
) -> None:
    hook_input = _cred("coder", "Write", file_path=path, content="x")
    assert_denied(hook_input, OUTSIDE, CREDENTIAL, "outside")
