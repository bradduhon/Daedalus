# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: in-process and subprocess runners for scripts/checks, each agent's chain, the split.
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from types import ModuleType

from lib import hook_io, jail, router
from lib.config import Config
from lib.jail import Decision, normalize_agent

from tests.conftest import REPO_ROOT

CHECKS = REPO_ROOT / "scripts" / "checks"
# 0044: the packet section 8 table at v2, one (script, flags) entry per hook, in order.
CHAINS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "repo-coder": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ("--no-pipes",)),
        ("network_tools", ()),
        ("git_push", ()),
        ("git_grammar", ("--allow", "coder")),
        ("unit_writes", ()),
        ("gh_classes", ()),
    ),
    "contract-spec": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("root_writes", ("--touch", "contracts,charter-specs")),
    ),
    "charter-docs": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ("--no-pipes",)),
        ("network_tools", ()),
        ("git_push", ()),
        ("git_grammar", ("--allow", "docs")),
        ("root_writes", ("--touch", "charter,docs", "--ledger-guard")),
        ("command_allowlist", ("--allow", "append_ledger,git,read")),
        ("gh_classes", ()),
    ),
    "security-auditor": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ()),
        ("network_tools", ()),
        ("read_only_bash", ("--git", "read-only")),
        ("gh_classes", ()),
    ),
    "nist-specialist": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ()),
        ("network_tools", ()),
        ("read_only_bash", ("--git", "specialist")),
        ("gh_classes", ()),
    ),
    "cis-specialist": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ()),
        ("network_tools", ()),
        ("read_only_bash", ("--git", "specialist")),
        ("gh_classes", ()),
    ),
    "web-researcher": (
        ("credential_paths", ()),
        ("tool_bound", ()),
        ("network_tools", ("--web",)),
    ),
    "standards-rules-specialist": (
        ("credential_paths", ()),
        ("tool_bound", ()),
    ),
    "pr-train-conductor": (
        ("credential_paths", ()),
        ("workspace_integrity", ()),
        ("tool_bound", ()),
        ("shell_tripwires", ("--no-pipes",)),
        ("network_tools", ("--gh",)),
        ("command_allowlist", ("--allow", "git,gh,gitleaks")),
        ("git_grammar", ("--allow", "conductor")),
        ("git_push", ("--conductor",)),
        ("gh_classes", ("--conductor",)),
    ),
}
_MODULES: dict[str, ModuleType] = {}


def load(script: str) -> ModuleType:
    # 0044: one import per script, by file path, as the router will load them.
    if script not in _MODULES:
        spec = importlib.util.spec_from_file_location(f"checks_{script}", CHECKS / f"{script}.py")
        assert spec is not None and spec.loader is not None, script
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[script] = module
    return _MODULES[script]


def evaluate(script: str, hook_input: dict[str, object], *flags: str) -> str | None:
    module = load(script)
    decision = hook_io.evaluate(hook_input, list(flags), module.judge, module.TOOLS, module.PARSER)
    return decision.reason


def first_deny(hook_input: dict[str, object], config: Config) -> tuple[str, str] | None:
    # 0044: first deny wins; hook_io.hook_config answers with the case's config.
    agent = normalize_agent(str(hook_input.get("agent_type") or "main"))
    saved = hook_io.hook_config
    hook_io.hook_config = lambda cwd: config
    try:
        for script, flags in CHAINS[agent]:
            reason = evaluate(script, hook_input, *flags)
            if reason is not None:
                return script, reason
    finally:
        hook_io.hook_config = saved
    return None


def decide(hook_input: dict[str, object], config: Config) -> Decision:
    denied = first_deny(hook_input, config)
    return Decision(denied is None, denied[1] if denied else None)


def judge(hook_input: dict[str, object], config: Config) -> Decision:
    # 0044: as scripts/enforce_agent_jail.py splits: Daedalus agents by the router, else lib.jail.
    raw = str(hook_input.get("agent_type") or "main")
    if router.routed(raw):
        allow, reason, _ = router.route(hook_input, REPO_ROOT)
        return Decision(allow, reason, normalize_agent(raw))
    return jail.decide(hook_input, config)


def run_script(
    script: str, stdin: str, *flags: str, raise_in_judge: bool = False
) -> dict[str, str]:
    # 0044: the standalone path, stdin JSON in and one line of decision JSON out.
    path = str(CHECKS / f"{script}.py")
    if raise_in_judge:
        code = (
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('hook', {path!r})\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "def boom(hook_input, flags):\n"
            "    raise RuntimeError('probe failure')\n"
            "mod.judge = boom\n"
            "sys.exit(mod.main())\n"
        )
        argv = [sys.executable, "-c", code, *flags]
    else:
        argv = [sys.executable, path, *flags]
    done = subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert len(lines) == 1, done.stdout
    out = json.loads(lines[0])["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] in {"allow", "deny"}
    return {"decision": out["permissionDecision"], "reason": out["permissionDecisionReason"]}


def payload(
    tool: str, cwd: str = "/work/repo", agent: str = "repo-coder", **tool_input: str
) -> str:
    return json.dumps(
        {"tool_name": tool, "tool_input": tool_input, "cwd": cwd, "agent_type": agent}
    )


# 0044: the four standard per-hook properties, each through the standalone script.
def outside_tools_allow(script: str, tool: str, *flags: str) -> None:
    assert run_script(script, payload(tool), *flags) == {"decision": "allow", "reason": ""}


def unknown_flag_denies(script: str, inside: str, *flags: str) -> None:
    got = run_script(script, inside, *flags, "--bogus")
    assert got == {
        "decision": "deny",
        "reason": f"hook {script} failed closed (unknown flag --bogus)",
    }


def malformed_input_denies(script: str, *flags: str) -> None:
    want = {
        "decision": "deny",
        "reason": f"hook {script} failed closed (hook input has no tool_name)",
    }
    for bad in ("", "not json", "[1, 2]", '{"tool_input": {}}', '{"tool_name": 3}'):
        assert run_script(script, bad, *flags) == want, bad


def internal_error_denies(script: str, inside: str, *flags: str) -> None:
    got = run_script(script, inside, *flags, raise_in_judge=True)
    want = f"hook {script} failed closed (RuntimeError: probe failure)"
    assert got == {"decision": "deny", "reason": want}, got
