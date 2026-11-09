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
from tests.hook_chain import CHAINS, decide, first_deny
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


# (form, what names it); the stores sit in {home}, the shell starts in the repo {home}/repo
# holding a .env. "grammar": main's grammar refuses it; "credential": the typed check names it.
PATHSPEC_HUNT = (
    ("git add ~/.aws/credentials", "grammar"),
    ("git add -- ~/.ssh/id_rsa", "grammar"),
    ("git -C ~/.ssh add id_rsa", "grammar"),
    ("git add ':(top)../.ssh/id_rsa'", "grammar"),
    ("git diff --no-index /dev/null ~/.aws/credentials", "grammar"),
    ("git show HEAD:.env", "credential"),
    ("git add {home}/.aws/credentials", "credential"),
    ("git add -- ../.ssh/id_rsa", "credential"),
    ("git -C {home}/.ssh add id_rsa", "credential"),
    ("git log -- {home}/.ssh/id_rsa", "credential"),
    ("git diff -- ../.aws/credentials", "credential"),
    ("git log -p -- .env", "credential"),
    ("git grep KEY -- .env", "credential"),
    ("git log -p -- '*.en?'", "credential"),
    ("git log -- ':(icase).ENV'", "credential"),
    ("git log -- ':(top).env'", "credential"),
    ("git show :.env", "credential"),
    ("git show HEAD:../.ssh/id_rsa", "credential"),
    # 228 tail: the operand slots these git reads share between a revision and a path.
    ("git blame .env", "credential"),
    ("git log -p .env", "credential"),
    ("git diff HEAD {home}/.ssh/id_rsa", "credential"),
    ("git show HEAD .env", "credential"),
    ("git grep KEY ../.aws/credentials", "credential"),
)
# 228 tail: a source path in a retyped git read slot; the coder's whole chain admits it.
CODER_KEPT = "git blame src/a.py"
# 228 tail: pathspecs that name no store stay as they were; a folder pathspec is no tree read.
PATHSPEC_KEPT = (
    "git add .",
    "git log -- src",
    "git diff -- ':(exclude).env'",
    "git log -- ':(literal)*.en?'",
    "git show HEAD:src/a.py",
    "git commit -m 'fix: .env loader'",
    CODER_KEPT,
)
ROLES = sorted({key.split(" (")[0] for key in CHAINS})


@pytest.fixture
def spec_repo(cred_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = cred_home / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".env").write_text("KEY=1\n")
    (cred_home / ".ssh").mkdir()
    (cred_home / ".aws").mkdir()
    monkeypatch.setattr(jail, "_train_scoped", lambda cwd, tool, tool_input: True)
    return repo


def _spec_payload(command: str, repo: Path, agent: str | None) -> dict[str, object]:
    payload: dict[str, object] = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(repo),
    }
    return {**payload, "agent_type": agent} if agent else payload


@pytest.mark.parametrize(("template", "named_by"), PATHSPEC_HUNT)
def test_a_store_named_as_a_git_pathspec_is_warned_for_main_and_refused_for_agents(
    spec_repo: Path, template: str, named_by: str
) -> None:
    # 228 tail: a grammar row is refused before the typed check; an admitted one is named by it.
    command = _form(template, spec_repo.parent)
    got = jail._admission(command, "main", str(spec_repo))[1]
    reason = jail._credential_reason("Bash", {"command": command}, str(spec_repo))
    assert isinstance(got, Refusal) == (named_by == "grammar"), (command, got)
    assert (reason is not None) == (named_by == "credential"), (command, reason)
    d = jail.decide(_spec_payload(command, spec_repo, None), CFG)
    assert d.warn and not d.allow, (command, d.reason)
    assert (reason or "Refused: ") in str(d.reason), (command, d.reason)
    for role in ROLES:
        deny = first_deny(_spec_payload(command, spec_repo, role), CFG)
        assert deny is not None, (role, command)
        assert (deny[0] == "credential_paths") == (named_by == "credential"), (role, command, deny)


@pytest.mark.parametrize("command", PATHSPEC_KEPT)
def test_a_pathspec_naming_no_store_is_not_a_credential_hit(spec_repo: Path, command: str) -> None:
    assert jail._credential_reason("Bash", {"command": command}, str(spec_repo)) is None, command
    d = jail.decide(_spec_payload(command, spec_repo, None), CFG)
    assert d.allow and not d.warn, (command, d.reason)
    for role in ROLES:
        deny = first_deny(_spec_payload(command, spec_repo, role), CFG)
        assert deny is None or deny[0] != "credential_paths", (role, command, deny)
        if command == CODER_KEPT and role == "coder":
            assert deny is None, (role, command, deny)


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
