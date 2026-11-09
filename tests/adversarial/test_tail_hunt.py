# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 tail hunt: the coder file's hunt list and the shell-semantics classes against the typed
# credential-path check and main's typed tripwires; an admitted form is named, a refused one warned.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail
from lib.admit import Refusal

from tests.conftest import CFG, CWD
from tests.hook_chain import decide
from tests.payloads import _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
# (hunt class, form); {home} is the test home holding the stores.
CREDENTIAL_HUNT = (
    ("leading option", "cat -A ~/.ssh/id_ed25519"),
    ("valued option value is a path", "grep -f ~/.ssh/id_ed25519 x"),
    ("--", "cat -- ~/.aws/credentials"),
    ("-", "cat - ~/.ssh/id_ed25519"),
    ("clustered flags", "grep -rn key ~/.aws"),
    ("unique long prefix", "grep --recurs key ~/.aws"),
    ("path command name", "/usr/bin/cat ~/.ssh/id_ed25519"),
    ("wrapper", "nice cat ~/.ssh/id_ed25519"),
    ("two wrappers", "nice timeout 5 cat ~/.ssh/id_ed25519"),
    ("NAME=value prefix", "LANG=C cat ~/.ssh/id_ed25519"),
    ("export in an earlier segment", "export D={home}/.ssh; cat $D/id_ed25519"),
    ("declare -x in an earlier segment", "declare -x D={home}/.ssh; cat $D/id_ed25519"),
    ("set -a in an earlier segment", "set -a; D={home}/.ssh; cat $D/id_ed25519"),
    ("subshell", "(cat ~/.ssh/id_ed25519)"),
    ("brace group", "{{ cat ~/.ssh/id_ed25519; }}"),
    ("pipe into the command", "ls | cat ~/.ssh/id_ed25519"),
    ("here-string", "cat <<< x ~/.ssh/id_ed25519"),
    ("heredoc, quoted delimiter", "cat <<'E' > ~/.ssh/authorized_keys\nk\nE"),
    ("heredoc, bare delimiter", "cat <<E > ~/.ssh/authorized_keys\nk\nE"),
    ("redirect before the command word", "< ~/.ssh/id_ed25519 cat"),
    ("$ in a word", "cat $HOME/.ssh/id_ed25519"),
    ("backtick", "cat `echo ~/.ssh/id_ed25519`"),
    ("glob in a word", "cat ~/.ss?/id_ed25519"),
    ("quoted $", 'cat "$HOME/.aws/credentials"'),
    ("$'..'", "cat $'{home}/.ssh/id_ed25519'"),
    ("SS-1 read builtin", "read D; cat $D/.ssh/id_ed25519"),
    ("SS-1 default-assigning expansion", "cat ${{D:={home}}}/.ssh/id_ed25519"),
    ("SS-2 search path prefix", "PATH=/x cat ~/.ssh/id_ed25519"),
    ("SS-3 shell body", "bash -c 'cat ~/.ssh/id_ed25519'"),
    ("SS-4 tilde in a redirect", "cat x > ~/.ssh/authorized_keys"),
    ("SS-5 git global -C", "git -C {home}/.ssh log"),
    ("SS-6 newline separator", "ls\ncat ~/.ssh/id_ed25519"),
    ("wrapper chdir", "env -C {home}/.ssh cat id_ed25519"),
    ("leading cd", "cd {home}/.aws && cat credentials"),
    ("tree read", "grep -r key ~"),
    ("tree read, rg hidden", "rg --hidden key ~"),
    ("tree read, cp -r", "cp -r ~ /tmp/x"),
)
# (hunt class, form, warning constant name); main is warned, never refused.
MAIN_HUNT = (
    ("default branch", "git push origin main", "WARN_DEFAULT_BRANCH"),
    ("quoted branch", 'git push origin "main"', "WARN_DEFAULT_BRANCH"),
    ("escaped branch", "git push origin ma\\in", "WARN_DEFAULT_BRANCH"),
    ("NAME=value prefix", "TZ=UTC git push origin main", "WARN_DEFAULT_BRANCH"),
    ("wrapper", "nohup git push origin main", "WARN_DEFAULT_BRANCH"),
    ("separator", "ls; git push -u origin master", "WARN_DEFAULT_BRANCH"),
    ("newline separator", "ls\ngit push origin main", "WARN_DEFAULT_BRANCH"),
    ("$ in the branch", "git push origin $B", "WARN_COMMAND"),
    ("brace in the branch", "git push origin ma{in,}", "WARN_COMMAND"),
    ("force flag", "git push --force origin x", "WARN_COMMAND"),
    ("recursive delete of /", "rm -rf /", "WARN_DELETE"),
    ("split flags", "rm -r -f /", "WARN_DELETE"),
    ("long option", "rm --recursive /", "WARN_DELETE"),
    ("--", "rm -rf -- /", "WARN_DELETE"),
    ("tilde target", "rm -rf ~", "WARN_COMMAND"),
    ("config key on a read", "git -c core.pager=x log", "WARN_COMMAND"),
    ("signing config on a read", "git -c commit.gpgsign=true log", "WARN_COMMAND"),
    ("data folder add", "git add .claude/daedalus/config.json", "WARN_DATA_DIR"),
    ("claude by name", "claude -p hi", "WARN_NESTED_CLAUDE"),
    ("claude under a wrapper", "timeout 5 claude -p hi", "WARN_NESTED_CLAUDE"),
    ("claude by path", "/usr/bin/claude", "WARN_NESTED_CLAUDE"),
    ("claude in a body", "bash -c 'claude -p hi'", "WARN_COMMAND"),
)


def _form(template: str, home: Path) -> str:
    return template.format(home=home)


@pytest.mark.parametrize(("klass", "template"), CREDENTIAL_HUNT)
def test_a_credential_hunt_form_is_named_or_refused(
    cred_home: Path, klass: str, template: str
) -> None:
    # 228 tail, 0224: a form main admits is named by the typed check; a refused one carries no
    # typed path, so main is warned with the refusal and an agent's grammar refuses it.
    (cred_home / ".ssh").mkdir()
    (cred_home / ".aws").mkdir()
    command = _form(template, cred_home)
    got = jail._admission(command, "main", CWD)[1]
    reason = jail._credential_reason("Bash", {"command": command}, CWD)
    if isinstance(got, Refusal):
        assert reason is None and got.text, (klass, command)
    else:
        assert reason is not None and "credential" in reason, (klass, command, reason)
    d = jail.decide(_b(None, command), CFG)
    assert d.warn and not d.allow, (klass, command, d.reason)
    for agent in ("coder", "auditor"):
        chain = decide(_b(agent, command), CFG)
        assert not chain.allow and not chain.warn, (klass, agent, command)


@pytest.mark.parametrize(("klass", "command", "warning"), MAIN_HUNT)
def test_a_main_tripwire_hunt_form_is_warned_by_name(
    fake_claude: Path, klass: str, command: str, warning: str
) -> None:
    # 0105, 0106, 228 tail: an admitted form meets the typed tripwire; a refused one is warned
    # with the grammar's refusal at its span. Main is never refused.
    d = jail.decide(_b(None, command), CFG)
    reason = str(d.reason)
    assert d.warn and not d.allow, (klass, command, reason)
    assert reason.startswith(f"{getattr(jail, warning)} The jail's finding: "), (klass, reason)
    # SA-5: a refusal names its span; a typed tripwire names its rule with its Next line.
    assert "Refused: " in reason or "Next:" in reason, (klass, reason)
