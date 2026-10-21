# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import NamedTuple

from lib import train_state, workspace
from lib.audit import project_root
from lib.audit_proof import integration_tip, tip_problem

CONDUCTOR = "pr-train-conductor"
# 0028: the allowed list intersected with the conductor's set; K1: pr edit changes the body only.
CONDUCTOR_GH = frozenset(
    {("pr", "create"), ("pr", "edit"), ("pr", "view"), ("pr", "list"), ("pr", "checks")}
    | {("run", "list"), ("run", "view"), ("run", "watch")}
)
ALLOWED_0028 = CONDUCTOR_GH | {("auth", "status"), ("issue", "view"), ("issue", "list")}
# B7: main reads during a train; pull request writes stay with the conductor.
MAIN_GH = ALLOWED_0028 - {("pr", "create"), ("pr", "edit")}
R_VERDICT = (
    "{what} needs an approved audit verdict on the tip of {branch}, or on its parent when the "
    "tip only adds the ledger commit; {detail} (spec 4.2, 3.5). "
    "Next: audit the exact tip, or record the operator's exception."
)
R_PR_HEAD = (
    "gh pr create may open a pull request only from the train branch {branch}, the tip the "
    "audit verdict covers (spec 4.2). Next: drop --head so the pull request opens from the "
    "current branch, or pass --head {branch}."
)
R_PR_CURRENT = (
    "gh pr create without --head opens the pull request from the checked-out branch, which "
    "is not the train branch {branch} the audit verdict covers (spec 4.2). "
    "Next: pass --head {branch} so the pull request opens from the audited branch."
)
# gh pr create flags that take a value; every other flag is boolean.
_PR_CREATE_SHORT_VALUE = frozenset("aBbFHlmprRTt")
_PR_CREATE_LONG_VALUE = frozenset(
    {"--assignee", "--base", "--body", "--body-file", "--head", "--label", "--milestone"}
    | {"--project", "--reviewer", "--repo", "--recover", "--template", "--title"}
)
CLASS_NEXT = {
    "merge": "the operator merges in the GitHub UI",
    "delete": "delete from your own shell if you mean it",
    "admin": "change repository settings from your own shell",
    "default-deny": "only the Push Train's conductor runs gh",
}
PUSH_NEXT = "push from your own shell, or through /daedalus:push-train"
EDIT_NEXT = "edit only the body with --body-file; the operator changes anything else on the PR"
_EDIT_BODY = frozenset({"--body", "--body-file", "-b", "-F"})
ADMIN_COMMANDS = frozenset({"secret", "variable", "ruleset"})
ADMIN_REPO = frozenset({"edit", "rename", "archive", "unarchive", "deploy-key"})
# gh api: short flags that take a value, and their long forms.
_API_SHORT_VALUE = frozenset("XfFHqtp")
_API_LONG_VALUE = frozenset(
    {"--method", "--raw-field", "--field", "--header", "--input", "--jq", "--template"}
    | {"--preview", "--hostname", "--cache"}
)
# issue 76: pflag value flags per gh command path; a path off the table keeps -R and --repo.
_GH_PERSISTENT = (frozenset("R"), frozenset({"--repo"}))
_READ_LONG = frozenset({"--jq", "--template", "--json", "--repo"})
_GH_VALUES: dict[tuple[str, ...], tuple[frozenset[str], frozenset[str]]] = {
    ("api",): (_API_SHORT_VALUE, _API_LONG_VALUE),
    ("pr", "create"): (_PR_CREATE_SHORT_VALUE, _PR_CREATE_LONG_VALUE),
    ("pr", "edit"): (
        frozenset("BbFmtR"),
        frozenset({"--base", "--body", "--body-file", "--milestone", "--title", "--repo"})
        | {"--add-assignee", "--add-label", "--add-project", "--add-reviewer"}
        | {"--remove-assignee", "--remove-label", "--remove-project", "--remove-reviewer"},
    ),
    ("pr", "comment"): (frozenset("bFR"), frozenset({"--body", "--body-file", "--repo"})),
    ("pr", "view"): (frozenset("qtR"), _READ_LONG),
    ("pr", "list"): (
        frozenset("AaBHlLqSstR"),
        _READ_LONG
        | {"--author", "--assignee", "--base", "--head", "--label", "--limit"}
        | {"--search", "--state", "--app"},
    ),
    ("pr", "checks"): (frozenset("iqtR"), _READ_LONG | {"--interval"}),
    ("run", "list"): (
        frozenset("bceLqstuwR"),
        _READ_LONG
        | {"--branch", "--commit", "--event", "--limit", "--status", "--user"}
        | {"--workflow", "--created"},
    ),
    ("run", "view"): (frozenset("ajqtR"), _READ_LONG | {"--attempt", "--job"}),
    ("run", "watch"): (frozenset("iR"), frozenset({"--interval", "--repo"})),
    ("issue", "view"): (frozenset("qtR"), _READ_LONG),
    ("issue", "list"): (
        frozenset("aAlLmsSqtR"),
        _READ_LONG
        | {"--assignee", "--author", "--label", "--limit", "--milestone"}
        | {"--search", "--state", "--mention", "--app"},
    ),
    ("auth", "status"): (frozenset("h"), frozenset({"--hostname"})),
}
R_GH_BUNDLE = (
    "gh flags the jail cannot pair with their values are refused: a bundle of short flags in "
    "one word (such as -dH) or a value flag given no value (issue 76). "
    "Next: give each short flag its own word and each value flag its value."
)


class GhFlag(NamedTuple):
    # issue 76: name as given (--head or -H); value None for a boolean flag.
    name: str
    value: str | None
    attached: bool  # a short flag's value inside its own word (-Hx, -H=x)


class GhArgs(NamedTuple):
    words: list[str]
    flags: list[GhFlag]


_MERGE_PATH = re.compile(r"(?:^|/)(?:pulls/[^/]+/merge|merges|merge-upstream)/?$")
_ADMIN_PATH = re.compile(
    r"^repos/[^/]+/[^/]+/?$|^orgs/|^user(?:/|$)|/branches/[^/]+/protection|/rulesets?(?:/|$)"
    r"|/collaborators|/hooks|/keys|/actions/(?:secrets|variables|permissions)|/environments"
    r"|/teams|/transfer|/topics|/pages|/vulnerability-alerts|/automated-security-fixes"
    r"|/invitations|/autolinks|/properties"
)
_MERGE_MUTATION = re.compile(r"\b(?:mergePullRequest|enqueuePullRequest|mergeBranch)\b")
_DELETE_MUTATION = re.compile(r"\bdelete[A-Z]\w*")
_ADMIN_MUTATION = re.compile(
    r"\b(?:update|create|archive|unarchive)Repository\w*|\b\w*BranchProtectionRule\b"
    r"|\b\w*Ruleset\b|\b\w*Collaborator\w*|\b\w*DeployKey\b"
)
# 0028: tokenizer refusal for main; a gh word or a git push anywhere is refused.
_GH_WORD = re.compile(r"(?<![\w.-])(?:[\w./-]*/)?gh(?![\w.-])")
_GIT_PUSH = re.compile(
    r"(?<![\w.-])(?:[\w./-]*/)?git(?:\s+(?:-[Cc]\s+\S+|-\S+))*\s+[\"']?push(?![\w-])"
)


def gh_args(args: list[str]) -> GhArgs | None:
    # issue 76: the one pflag parse of the words after gh; None for a bundle or a missing value.
    words: list[str] = []
    flags: list[GhFlag] = []
    short, long = _GH_PERSISTENT
    i = 0
    while i < len(args):
        arg = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if arg == "--":
            words += args[i + 1 :]
            break
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if eq or name not in long:
                flags.append(GhFlag(name, value if eq else None, False))
            elif nxt is None:
                return None
            else:
                flags.append(GhFlag(name, nxt, False))
                i += 1
        elif arg.startswith("-") and len(arg) > 1:
            letter, rest = arg[:2], arg[2:]
            if arg[1] not in short:
                # issue 76: a bundle (-dH x) rests on the tables naming every boolean; refuse it.
                if rest:
                    return None
                flags.append(GhFlag(letter, None, False))
            elif rest:
                flags.append(GhFlag(letter, rest.removeprefix("="), True))
            elif nxt is None:
                return None
            else:
                flags.append(GhFlag(letter, nxt, False))
                i += 1
        else:
            words.append(arg)
            if len(words) <= 2:
                short, long = _GH_VALUES.get(tuple(words), (short, long))
        i += 1
    return GhArgs(words, flags)


def _api_parts(parsed: GhArgs) -> tuple[str | None, list[str], bool, str]:
    # Returns (explicit method, -f/-F values, --input given, endpoint).
    method: str | None = None
    fields: list[str] = []
    body = False
    for flag in parsed.flags:
        if flag.name in {"-X", "--method"}:
            method = (flag.value or "").upper()
        elif flag.name in {"-f", "-F", "--raw-field", "--field"}:
            fields.append(flag.value or "")
        elif flag.name == "--input":
            body = True
    return method, fields, body, (parsed.words[1:2] or [""])[0]


def _endpoint(raw: str) -> str:
    path = re.sub(r"^https?://[^/]+", "", raw).split("?", 1)[0]
    return path.lstrip("/")


def _classify_api(parsed: GhArgs) -> tuple[str, str]:
    explicit, fields, body, raw = _api_parts(parsed)
    method = explicit or ("POST" if fields or body else "GET")
    path = _endpoint(raw)
    detail = f"api {method} {path or '(no endpoint)'}"
    if method == "DELETE":
        return "delete", detail
    if path == "graphql":
        query = " ".join(f.partition("=")[2] for f in fields if f.partition("=")[0] == "query")
        if body or query.startswith("@"):
            return "default-deny", detail
        if _MERGE_MUTATION.search(query):
            return "merge", detail
        if _DELETE_MUTATION.search(query):
            return "delete", detail
        if "mutation" in query and _ADMIN_MUTATION.search(query):
            return "admin", detail
        return "default-deny", detail
    if method == "GET":
        return "default-deny", detail
    if _MERGE_PATH.search(path):
        return "merge", detail
    if _ADMIN_PATH.search(path):
        return "admin", detail
    return "default-deny", detail


def _body_only_edit(parsed: GhArgs) -> bool:
    # K1: pr edit passes only with body flags and at most one PR selector.
    words, flags = parsed
    return (
        words[:2] == ["pr", "edit"] and len(words) <= 3 and all(f.name in _EDIT_BODY for f in flags)
    )


def classify(tokens: list[str]) -> tuple[str, str]:
    # 0028: merge, delete and admin are refused for everyone; everything off the list is denied.
    args = tokens[1:]
    parsed = gh_args(args)
    if parsed is None:
        return "default-deny", "(flags without their values)"
    words = parsed.words
    if words[:1] == ["api"]:
        return _classify_api(parsed)
    cmd, sub = (words + ["", ""])[:2]
    detail = " ".join(w for w in (cmd, sub) if w) or "(no subcommand)"
    if "merge" in cmd or "merge" in sub:
        return "merge", detail
    deleting = any(
        a.split("=", 1)[0] in {"--delete-branch", "--delete-last", "--cleanup-tag"} for a in args
    ) or ((cmd, sub) == ("pr", "close") and any(re.fullmatch(r"-[a-zA-Z]*d", a) for a in args))
    if sub.startswith("delete") or deleting:
        return "delete", detail
    if cmd in ADMIN_COMMANDS or (cmd == "repo" and sub in ADMIN_REPO):
        return "admin", detail
    if (cmd, sub) == ("pr", "edit") and not _body_only_edit(parsed):
        return "default-deny", detail
    if (cmd, sub) in ALLOWED_0028:
        return "allow", detail
    return "default-deny", detail


def allowlist_applies(agent: str, cwd: str, command: str = "") -> bool:
    # 0035: main and unknown agents meet the gh gate only while a train marks the repo.
    from lib.jail import KNOWN_AGENTS, _marked_repo  # jail imports this module.

    if agent in KNOWN_AGENTS and agent != "main":
        return True
    return os.path.isabs(cwd) and _marked_repo(cwd, "Bash", {"command": command}) is not None


def conductor_gh_refusal() -> str:
    # 0001, 0028: built from CONDUCTOR_GH, so the refusal names exactly the built set.
    groups = [
        f"gh {cmd} " + ", ".join(sorted(sub for c, sub in CONDUCTOR_GH if c == cmd))
        for cmd in sorted({c for c, _ in CONDUCTOR_GH})
    ]
    return (
        f"conductor gh is limited to {' and '.join(groups)}; the operator is the merge gate "
        "(0001). Next: report the PR URL."
    )


def _allowed(agent: str) -> frozenset[tuple[str, str]]:
    if agent == CONDUCTOR:
        return CONDUCTOR_GH
    return MAIN_GH if agent == "main" else frozenset()


def _gh_reason(agent: str, tokens: list[str]) -> str | None:
    if gh_args(tokens[1:]) is None:
        return R_GH_BUNDLE
    klass, detail = classify(tokens)
    if klass == "allow" and tuple(detail.split()) in _allowed(agent):
        return None
    if klass == "allow":
        return (
            f"gh {detail} is not on the {agent} gh list (0028). Next: {CLASS_NEXT['default-deny']}."
        )
    nxt = EDIT_NEXT if agent == CONDUCTOR and detail == "pr edit" else CLASS_NEXT[klass]
    return (
        f"gh {detail} is a {klass} command, refused while a train runs and to every "
        f"Daedalus agent (0028, 0035). Next: {nxt}."
    )


def _push_reason(agent: str) -> str | None:
    if agent == CONDUCTOR:
        return None
    return f"git push runs only in the Push Train's conductor (0028, 0030). Next: {PUSH_NEXT}."


def _fallback_reason(agent: str, command: str) -> str | None:
    if agent == "main" and command.strip() == "gh auth status":
        return None
    if _GH_WORD.search(command):
        return (
            "this command could not be parsed and names gh, so it is refused (0028). "
            f"Next: run one plain gh command; {CLASS_NEXT['default-deny']}."
        )
    if _GIT_PUSH.search(command):
        return _push_reason(agent)
    return None


def gh_reason(agent: str, command: str, segments: list[list[str]] | None) -> str | None:
    # 0028: every gh and git push segment; None segments means the regex fallback.
    if segments is None:
        return _fallback_reason(agent, command)
    from lib.shell import _git_subcommand

    for tokens in segments:
        name = os.path.basename(tokens[0]) if tokens else ""
        if name == "gh":
            reason = _gh_reason(agent, tokens)
        elif name == "git" and _git_subcommand(tokens) == "push":
            reason = _push_reason(agent)
        else:
            reason = None
        if reason:
            return reason
    return None


def _verdict_detail(cwd: str, train: str, branch: str) -> str | None:
    # spec 4.2: state through train_state.load, never a reply file; the marker names the branch.
    repo = project_root(cwd)
    try:
        state = train_state.load(repo, train)
    except train_state.TrainStateError:
        return "no train state is readable"
    tip = integration_tip(repo, train)
    if tip is None:
        return f"{branch} does not resolve to a commit in {cwd}"
    exception = train_state.record(state, train_state.EXCEPTION)
    ledger_id = exception.get("ledger_id")
    if isinstance(ledger_id, str) and ledger_id and exception.get("tip") == tip:
        return None
    verdict = train_state.record(state, train_state.VERDICT)
    status = verdict.get("status")
    if not verdict:
        return "no verdict is recorded"
    if status != "approved":
        return f"the recorded verdict is {status if isinstance(status, str) else 'unreadable'}"
    # 59, spec 3.5: the same judged-tip rule the approved proof reads.
    return tip_problem(repo, verdict.get("tip"), tip)


def _active_train(cwd: str) -> str | None:
    return train_state.active_train(project_root(cwd)) if os.path.isabs(cwd) else None


def verdict_reason(cwd: str, what: str) -> str | None:
    # spec 4.2: a push or pr create passes on the approved tip or an exception for that tip.
    # The charter push and the -R charter pr create are gated on this project's integration tip.
    train = _active_train(cwd)
    if train is None:
        detail = "no train is active here"
        return R_VERDICT.format(what=what, branch="the train branch", detail=detail)
    branch = f"daedalus/{train}"
    detail = _verdict_detail(cwd, train, branch)
    return None if detail is None else R_VERDICT.format(what=what, branch=branch, detail=detail)


def pr_create_reason(tokens: list[str], cwd: str) -> str | None:
    # spec 4.2: --head names only the marker's train branch, the tip the verdict covers.
    parsed = gh_args(tokens[1:])
    if parsed is None:
        return R_GH_BUNDLE
    train = _active_train(cwd)
    if train is not None:
        branch = f"daedalus/{train}"
        heads = [f.value or "" for f in parsed.flags if f.name in {"--head", "-H"}]
        if any(head != branch for head in heads):
            return R_PR_HEAD.format(branch=branch)
        if not heads and _current_branch(cwd) != branch:
            return R_PR_CURRENT.format(branch=branch)
    return verdict_reason(cwd, "gh pr create")


def _current_branch(cwd: str) -> str | None:
    # spec 4.2: with no --head, gh opens the pull request from the checked-out branch.
    try:
        found = workspace._run(Path(cwd), "symbolic-ref", "--quiet", "--short", "HEAD")
    except (OSError, workspace.WorkspaceError):
        return None
    return found.stdout.strip() if found.returncode == 0 else None
