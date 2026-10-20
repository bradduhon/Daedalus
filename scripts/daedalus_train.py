#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0032, spec 3.5: the train runner's command line; the session runs one subcommand per step.
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.agent_models import AgentModelError, resolve  # noqa: E402
from lib.audit import DataDirError  # noqa: E402
from lib.config import ConfigError, load_config  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.train_runner import (  # noqa: E402
    EXIT_OK,
    EXIT_STOP,
    Outcome,
    check_reply,
    choice,
    progress,
    record_exception,
    record_plan,
    record_verdict,
    start,
    state_lines,
    step,
    stop,
)
from lib.train_state import TrainStateError  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Daedalus train runner: start, step, check-reply, state, stop, progress, "
        "choice, plan, exception, verdict, model. Exit 0 action "
        "taken, 1 stopped with a Next line, 2 routed failure, 3 operator question, 4 waiting."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    begin = sub.add_parser("start")
    begin.add_argument("--repo", type=Path, required=True)
    begin.add_argument("--train", required=True)
    begin.add_argument("--output")
    for name in ("step", "state"):
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
    plan = sub.add_parser("plan")
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument("--path", type=Path, required=True)
    waive = sub.add_parser("exception")
    waive.add_argument("--repo", type=Path, required=True)
    waive.add_argument("--ledger-id", dest="ledger_id", required=True)
    judged = sub.add_parser("verdict")
    judged.add_argument("--repo", type=Path, required=True)
    judged.add_argument("--status", required=True)
    judged.add_argument("--round", dest="round_", type=int, required=True)
    judged.add_argument("--seq", type=int)
    # 0109, 59, pin C3 -> C5: the auditor's finding list and the tip its verdict line names.
    judged.add_argument("--findings", type=Path)
    judged.add_argument("--tip")
    # spec 4, pin C3 -> C5: the effective model of one catalog agent, inside or outside a train.
    model = sub.add_parser("model")
    model.add_argument("--repo", type=Path, required=True)
    model.add_argument("--agent", required=True)
    model.add_argument("--override")
    return parser


def _model(repo: Path, agent: str, override: str | None) -> Outcome:
    try:
        return Outcome(EXIT_OK, [resolve(agent, load_config(cwd=str(repo)), override)])
    except (AgentModelError, ConfigError, DataDirError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])


def _repo_refusal(given: Path) -> str | None:
    # 63, pin C3 -> C4: --repo realpaths to the project root of the process cwd, or refuses.
    root = project_root(Path.cwd())
    if os.path.realpath(given) == os.path.realpath(root):
        return None
    return (
        f"--repo {given} is not the project root of the working directory ({root}). "
        f"Next: run the command from {given}, or pass --repo {root}."
    )


def _dispatch(args: argparse.Namespace) -> Outcome:
    repo = args.repo.resolve()
    if args.action == "start":
        return start(repo, args.train, args.output)
    if args.action == "step":
        return step(repo)
    if args.action == "progress":
        return progress(repo)
    if args.action == "choice":
        return choice(repo, args.chose, args.over, args.cost, args.phase)
    if args.action == "plan":
        return record_plan(repo, args.path)
    if args.action == "exception":
        return record_exception(repo, args.ledger_id)
    if args.action == "verdict":
        if args.status == "approved" and args.tip is None:
            # pin C3 -> C5: an approval always names the tip the auditor judged.
            return Outcome(
                EXIT_STOP,
                [
                    "verdict --status approved requires --tip. Next: rerun verdict with --tip "
                    "set to the tip= value of the auditor's verdict line."
                ],
            )
        return record_verdict(repo, args.status, args.round_, args.seq, args.tip, args.findings)
    if args.action == "model":
        return _model(repo, args.agent, args.override)
    if args.action == "check-reply":
        return check_reply(repo, args.stage)
    if args.action == "state":
        return state_lines(repo)
    return stop(repo, args.reason, args.next_action)


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    refusal = _repo_refusal(args.repo)
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
