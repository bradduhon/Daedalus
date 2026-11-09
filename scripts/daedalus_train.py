#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0032, spec 3.5: the train runner's command line; the session runs one subcommand per step.
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import assets, git, packs, writer_mode  # noqa: E402
from lib.agent_aliases import current as current_name  # noqa: E402
from lib.agent_models import AgentModelError, resolve  # noqa: E402
from lib.audit import DataDirError  # noqa: E402
from lib.briefs import BriefError, ask_file_problems, brief_file_problems  # noqa: E402
from lib.config import ConfigError, load_config  # noqa: E402
from lib.git import GitTimeout  # noqa: E402
from lib.manifest import Assets, ManifestError  # noqa: E402
from lib.manifest import load as load_manifest  # noqa: E402
from lib.passes import PassError, write_pass  # noqa: E402
from lib.passes import load as load_pass  # noqa: E402
from lib.project_root import project_root, repo_refusal  # noqa: E402
from lib.train_runner import (  # noqa: E402
    EXIT_OK,
    EXIT_STOP,
    Outcome,
    check_reply,
    choice,
    coder_model,
    contract,
    dispatch_unit,
    finish_unit,
    progress,
    reaudit,
    record_docs_verdict,
    record_exception,
    record_ledger,
    record_plan,
    record_unit_exception,
    record_verdict,
    refuted,
    resume,
    route_unit,
    start,
    state_lines,
    step,
    stop,
    summary,
)
from lib.train_state import TrainStateError, active_train  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Daedalus train runner: start, step, check-reply, state, stop, progress, "
        "choice, plan, contract, exception, verdict, reaudit, resume, ledger, summary, model, "
        "brief-check, ask-check, packs, writer-clear, assets, refuted, grant, dispatch, route, "
        "finish-unit. "
        "Exit 0 action "
        "taken, 1 stopped with a Next line, 2 routed failure, 3 operator question, 4 waiting."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    begin = sub.add_parser("start")
    begin.add_argument("--repo", type=Path, required=True)
    begin.add_argument("--train", required=True)
    begin.add_argument("--output")
    # pin D1 -> D6: reaudit and resume run from the main session; ledger from the orchestrator.
    # W3.2: summary writes <train-id>-summary.md from train state and the audit logs.
    # 0156: contract prints `contract: skip` or `contract: required (<reason>)`.
    for name in ("step", "state", "reaudit", "resume", "summary", "contract"):
        sub.add_parser(name).add_argument("--repo", type=Path, required=True)
    check = sub.add_parser("check-reply")
    check.add_argument("--repo", type=Path, required=True)
    check.add_argument("--stage", required=True)
    halt = sub.add_parser("stop")
    halt.add_argument("--repo", type=Path, required=True)
    halt.add_argument("--reason", required=True)
    halt.add_argument("--next", dest="next_action")
    # 0085, 0089: the operator view and the records the plan and verdict gates read.
    sub.add_parser("progress").add_argument("--repo", type=Path, required=True)
    chose = sub.add_parser("choice")
    chose.add_argument("--repo", type=Path, required=True)
    chose.add_argument("--chose", required=True)
    chose.add_argument("--over", required=True)
    chose.add_argument("--cost", required=True)
    chose.add_argument("--phase")
    # 0129: the driver that decided and the rule number or principle id that settled it.
    chose.add_argument("--driver")
    chose.add_argument("--rule")
    plan = sub.add_parser("plan")
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument("--path", type=Path, required=True)
    # 0133, 0139: one exemption per finding, with how the operator chose to track it.
    waive = sub.add_parser("exception")
    waive.add_argument("--repo", type=Path, required=True)
    waive.add_argument("--ledger-id", dest="ledger_id", required=True)
    # 229: the verify-phase form names a unit and one row of its newest refuted verdict.
    target = waive.add_mutually_exclusive_group(required=True)
    target.add_argument("--finding")
    target.add_argument("--unit")
    waive.add_argument("--row", type=int)
    waive.add_argument("--tracking", required=True)
    waive.add_argument("--other")
    judged = sub.add_parser("verdict")
    judged.add_argument("--repo", type=Path, required=True)
    judged.add_argument("--status", required=True)
    # 67: the round is derived from train state; a given --round must agree with it.
    judged.add_argument("--round", dest="round_", type=int)
    judged.add_argument("--seq", type=int)
    # 0109, 59, pin C3 -> C5: the auditor's finding list and the tip its verdict line names.
    judged.add_argument("--findings", type=Path)
    judged.add_argument("--tip")
    # 0131: --gate docs records the docs verifier's verdict, verified or refuted.
    judged.add_argument("--gate", choices=("security", "docs"), default="security")
    # 0131: --judged is the Docs tip sha the docs verifier judged, the docs branch head.
    judged.add_argument("--judged")
    ledger = sub.add_parser("ledger")
    ledger.add_argument("--repo", type=Path, required=True)
    ledger.add_argument("--sha", required=True)
    ledger.add_argument("--ids", required=True)
    # spec 4, pin C3 -> C5: the effective model of one catalog agent, inside or outside a train.
    model = sub.add_parser("model")
    model.add_argument("--repo", type=Path, required=True)
    model.add_argument("--agent", required=True)
    model.add_argument("--override")
    # 0187: --unit picks the coder's model from coder_models and records it on the unit.
    model.add_argument("--unit")
    # issue 187: one REFUTED verifier reply recorded on the unit the model command reads.
    refute = sub.add_parser("refuted")
    refute.add_argument("--repo", type=Path, required=True)
    refute.add_argument("--unit", required=True)
    # issue 187: an operator-check Fail counts as one refutation, keyed by its check text.
    refute.add_argument("--operator-check", dest="operator_check")
    # 0153, 0157 (12.5): a decision brief checked at the manifest literacy level.
    brief = sub.add_parser("brief-check")
    brief.add_argument("--repo", type=Path, required=True)
    brief.add_argument("--brief", type=Path, required=True)
    # 0199, 0200: one brainstorm question's reader text, always checked at plain.
    ask = sub.add_parser("ask-check")
    ask.add_argument("--repo", type=Path, required=True)
    ask.add_argument("--file", type=Path, required=True)
    # prepush-2026-10-27 finding 6, 0157: the pack check before any frameworks rulebook runs.
    packs_cmd = sub.add_parser("packs")
    packs_cmd.add_argument("--repo", type=Path, required=True)
    # 0192: the audit's merged range; a pack with triggers is listed only on a matching path.
    packs_cmd.add_argument("--diff")
    # 0190: the operator empties a writer queue a dispatch that never started left behind.
    sub.add_parser("writer-clear").add_argument("--repo", type=Path, required=True)
    # 0192: the asset pathspec tail every judge's diff line and the secret scan copy.
    tail = sub.add_parser("assets")
    tail.add_argument("--repo", type=Path, required=True)
    tail.add_argument("--base", required=True)
    tail.add_argument("--tip", required=True)
    # 233: the main session's sealed one-time pass; the command text comes from a file only.
    grant = sub.add_parser("grant")
    grant.add_argument("--repo", type=Path, required=True)
    grant.add_argument("--agent", required=True)
    grant.add_argument("--cwd", required=True)
    grant.add_argument("--reason", required=True)
    grant.add_argument("--ledger-id", dest="ledger_id", required=True)
    grant.add_argument("--command-file", dest="command_file", type=Path, required=True)
    # 0230: the composed record calls; each prints one line for the State Block row.
    send = sub.add_parser("dispatch")
    send.add_argument("--repo", type=Path, required=True)
    send.add_argument("--unit", required=True)
    send.add_argument("--warm")
    routed = sub.add_parser("route")
    routed.add_argument("--repo", type=Path, required=True)
    routed.add_argument("--unit", required=True)
    routed.add_argument("--verdict", choices=("VERIFIED", "REFUTED"), required=True)
    routed.add_argument("--rows", type=int)
    done = sub.add_parser("finish-unit")
    done.add_argument("--repo", type=Path, required=True)
    done.add_argument("--unit", required=True)
    done.add_argument("--next", dest="next_unit")
    done.add_argument("--warm")
    done.add_argument("--note", action="append", default=[])
    return parser


def _grant(repo: Path, args: argparse.Namespace) -> Outcome:
    # 233: read whole and undecoded by newline, so the digest is over the exact command.
    try:
        command = args.command_file.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return Outcome(EXIT_STOP, [f"grant: the command file could not be read ({exc})."])
    try:
        path = write_pass(repo, args.agent, command, args.cwd, args.reason, args.ledger_id)
    except PassError as exc:
        return Outcome(EXIT_STOP, [f"grant: {exc}"])
    written = load_pass(path)
    expires = written.expires if written is not None else "unknown"
    return Outcome(EXIT_OK, [f"pass written sha256={path.stem[:12]} expires={expires}"])


PACKS_NEXT = "Next: run /daedalus:doctor and fix each pack it names, then run /daedalus:run again."
# 0192: two revisions joined by ... or .., never an option git would read.
DIFF_RANGE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@^-]*\.\.\.?[A-Za-z0-9_][A-Za-z0-9._/@^-]*")


def _changed(repo: Path, diff: str) -> list[str] | str:
    # 0192: the changed paths of a merged range, or the reason git could not list them.
    if not DIFF_RANGE.fullmatch(diff):
        return f"packs: --diff {diff!r} is not a <base>...<branch> range"
    try:
        done = git.run(["diff", "--name-only", diff, "--"], repo)
    except (OSError, git.GitTimeout) as exc:
        return f"packs: git diff --name-only {diff} could not run ({exc})"
    if done.returncode != 0:
        return f"packs: git diff --name-only {diff} failed: {done.stderr.strip()}"
    return [line for line in done.stdout.splitlines() if line]


def _packs(repo: Path, diff: str | None = None) -> Outcome:
    # 0157: every pack folder the train reads passes pack_problems, or the train stops.
    try:
        folders = packs.pack_folders(repo)
        problems = [f"pack {f.name}: {p}" for f in folders for p in packs.pack_problems(f)]
        unknown = packs.unknown_named(repo)
    except (ManifestError, OSError) as exc:
        return Outcome(EXIT_STOP, [f"packs: {exc}", PACKS_NEXT])
    problems += [
        f"pack {ident}: frameworks.packs names {ident}, which is not a pack Daedalus ships"
        for ident in unknown
    ]
    if not folders and diff is not None and not problems:
        # 0192: an audit with no pack to read goes on; only a broken pack stops it.
        return Outcome(EXIT_OK, ["Packs: none", "Triggered: none"])
    if not folders:
        return Outcome(
            EXIT_STOP,
            [
                "No control pack was found for the compliance check. Next: run "
                "/daedalus:doctor, then fix the frameworks block of service-manifest.json."
            ],
        )
    if problems:
        return Outcome(EXIT_STOP, [*problems, PACKS_NEXT])
    if diff is None:
        return Outcome(EXIT_OK, [f"Packs: {', '.join(str(f) for f in folders)}"])
    changed = _changed(repo, diff)
    if isinstance(changed, str):
        return Outcome(EXIT_STOP, [changed, PACKS_NEXT])
    chosen, matched = packs.select_packs(folders, changed)
    return Outcome(
        EXIT_OK,
        [
            f"Packs: {', '.join(str(f) for f in chosen) or 'none'}",
            f"Triggered: {', '.join(str(f) for f in matched) or 'none'}",
        ],
    )


def _brief_check(repo: Path, brief: Path) -> Outcome:
    try:
        level, problems = brief_file_problems(repo, brief)
    except (BriefError, ManifestError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    if not problems:
        return Outcome(EXIT_OK, ["brief ok"])
    lines = [f"brief: {problem}" for problem in problems]
    lines.append(
        f"Next: rewrite each named question, context sentence or option label at the {level} "
        "level, then run brief-check again."
    )
    return Outcome(EXIT_STOP, lines)


def _ask_check(question: Path) -> Outcome:
    try:
        problems = ask_file_problems(question)
    except BriefError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    if not problems:
        return Outcome(EXIT_OK, ["question ok"])
    lines = [f"question: {problem}" for problem in problems]
    lines.append("Next: reword each named sentence in plain words, then run ask-check again.")
    return Outcome(EXIT_STOP, lines)


def _assets(repo: Path, base: str, tip: str) -> Outcome:
    try:
        loaded = load_manifest(repo)
        declared = loaded.assets if loaded is not None else Assets()
        found = assets.exclusion(repo, base, tip, declared)
    except (ManifestError, assets.AssetsError, GitTimeout, OSError) as exc:
        return Outcome(EXIT_STOP, [f"assets: {exc}"])
    return Outcome(EXIT_OK, assets.lines(found))


def _writer_clear(repo: Path) -> Outcome:
    # 0190: main session only; the orchestrator's train class does not admit it.
    root = project_root(repo)
    train = active_train(root)
    if train is None:
        return Outcome(
            EXIT_STOP,
            [
                f"no run is marked in {root}, so no writer queue waits. "
                "Next: mark a run before you clear its queue."
            ],
        )
    removed = writer_mode.clear(root, train)
    return Outcome(EXIT_OK, [f"writer queue cleared train={train} removed={removed}"])


def _model(repo: Path, agent: str, override: str | None, unit: str | None = None) -> Outcome:
    if unit is not None:
        if current_name(agent) != "coder" or override is not None:
            return Outcome(
                EXIT_STOP,
                [
                    "model --unit picks a coder's model and takes no --override. "
                    "Next: rerun it as model --agent coder --unit <unit id>."
                ],
            )
        return coder_model(repo, unit)
    try:
        return Outcome(EXIT_OK, [resolve(agent, load_config(cwd=str(repo)), override, repo=repo)])
    except (AgentModelError, ConfigError, DataDirError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])


def _dispatch(args: argparse.Namespace) -> Outcome:
    repo = args.repo.resolve()
    if args.action == "start":
        return start(repo, args.train, args.output)
    if args.action == "step":
        return step(repo)
    if args.action == "progress":
        return progress(repo)
    if args.action == "choice":
        return choice(repo, args.chose, args.over, args.cost, args.phase, args.driver, args.rule)
    if args.action == "plan":
        return record_plan(repo, args.path)
    if args.action == "contract":
        return contract(repo)
    if args.action == "exception":
        if (args.unit is None) != (args.row is None):
            return Outcome(
                EXIT_STOP,
                [
                    "--row goes with --unit and --unit needs --row. Next: rerun exception with "
                    "--unit <unit id> --row <n>, or with --finding alone."
                ],
            )
        if args.unit is not None:
            return record_unit_exception(
                repo, args.ledger_id, args.unit, args.row, args.tracking, args.other
            )
        return record_exception(repo, args.ledger_id, args.finding, args.tracking, args.other)
    if args.action == "verdict":
        if args.gate == "docs":
            if args.round_ is not None or args.seq is not None:
                return Outcome(
                    EXIT_STOP,
                    [
                        "verdict --gate docs takes no --round or --seq; the docs verdict has no "
                        "audit round. Next: rerun it with --status and, when refuted, --findings."
                    ],
                )
            if args.status == "verified" and args.judged is None:
                # 0131: a verified docs verdict always names the docs tip the verifier judged.
                return Outcome(
                    EXIT_STOP,
                    [
                        "verdict --gate docs --status verified requires --judged, the Docs tip "
                        "sha the verifier judged, and this call passed none. Next: rerun it with "
                        "--judged set to the Docs tip: sha of the verifier dispatch."
                    ],
                )
            if args.status != "verified" and args.judged is not None:
                return Outcome(
                    EXIT_STOP,
                    [
                        "verdict --judged belongs to --gate docs --status verified only. Next: "
                        "rerun the docs verdict without --judged."
                    ],
                )
            return record_docs_verdict(repo, args.status, args.tip, args.findings, args.judged)
        if args.judged is not None:
            return Outcome(
                EXIT_STOP,
                [
                    "verdict --judged belongs to --gate docs only. Next: rerun the security "
                    "verdict with --tip and without --judged."
                ],
            )
        if args.status == "approved" and args.tip is None:
            # pin C3 -> C5: an approval always names the tip the auditor judged.
            return Outcome(
                EXIT_STOP,
                [
                    "verdict --status approved requires --tip, the tip the auditor judged, and "
                    "this call passed none. Next: rerun verdict with --tip set to the tip= value "
                    "of the auditor's verdict line."
                ],
            )
        return record_verdict(repo, args.status, args.round_, args.seq, args.tip, args.findings)
    if args.action == "reaudit":
        return reaudit(repo)
    if args.action == "resume":
        return resume(repo)
    if args.action == "ledger":
        return record_ledger(repo, args.sha, args.ids)
    if args.action == "summary":
        return summary(repo)
    if args.action == "model":
        return _model(repo, args.agent, args.override, args.unit)
    if args.action == "refuted":
        return refuted(repo, args.unit, args.operator_check)
    if args.action == "brief-check":
        return _brief_check(repo, args.brief)
    if args.action == "ask-check":
        return _ask_check(args.file)
    if args.action == "packs":
        return _packs(repo, args.diff)
    if args.action == "writer-clear":
        return _writer_clear(repo)
    if args.action == "assets":
        return _assets(repo, args.base, args.tip)
    if args.action == "grant":
        return _grant(repo, args)
    if args.action == "dispatch":
        return dispatch_unit(repo, args.unit, args.warm)
    if args.action == "route":
        return route_unit(repo, args.unit, args.verdict, args.rows)
    if args.action == "finish-unit":
        return finish_unit(repo, args.unit, args.next_unit, args.note, args.warm)
    if args.action == "check-reply":
        return check_reply(repo, args.stage)
    if args.action == "state":
        return state_lines(repo)
    return stop(repo, args.reason, args.next_action)


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    refusal = repo_refusal(args.repo, Path.cwd())
    if refusal is not None:
        print(refusal)
        return EXIT_STOP
    try:
        outcome = _dispatch(args)
    except TrainStateError as exc:
        outcome = Outcome(EXIT_STOP, [str(exc)])
    print("\n".join(outcome.lines))
    return outcome.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
