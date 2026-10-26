# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: runs each Daedalus agent's calls through the hooks its agent file names, in-process.
# First deny wins; no binding, an unreadable agent file or a failing hook denies.
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from lib import agent_files, hook_io, jail
from lib.train_scope import policed_outside_train

ROUTER = "router"
R_MAIN = "the main session is not routed (0044)."
_NEXT = "Next: add the agent file with its shape and hooks block, or start a catalog agent."
R_NO_FILE = "no binding exists for agent '{name}': agents/{name}.md is missing (0044). " + _NEXT
R_NO_HOOKS = (
    "no binding exists for agent '{name}': agents/{name}.md has no hooks block (0044). " + _NEXT
)
# 0044: one import per hook script per process, keyed by script stem.
_MODULES: dict[str, ModuleType] = {}
# 0136, D.5: checks every routed agent meets after its own hooks, loaded from this plugin tree.
EVERY_AGENT = (agent_files.Hook("excluded_roots", ()),)
_OWN_ROOT = Path(__file__).resolve().parents[2]
_EVERY_MODULES: dict[str, ModuleType] = {}


def routed(raw_agent: str) -> bool:
    # 0023, 0044: every Daedalus agent but the main session, in a train or not.
    return policed_outside_train(raw_agent) and jail.normalize_agent(raw_agent) != "main"


def _module(
    script: str, plugin_root: Path, cache: dict[str, ModuleType] | None = None
) -> ModuleType:
    cache = _MODULES if cache is None else cache
    module = cache.get(script)
    if module is None:
        path = plugin_root / "scripts" / "checks" / f"{script}.py"
        spec = importlib.util.spec_from_file_location(f"daedalus_checks_{script}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"no loader for {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cache[script] = module
    return module


def _run(
    hook: agent_files.Hook,
    hook_input: dict[str, object],
    plugin_root: Path,
    cache: dict[str, ModuleType] | None = None,
) -> str | None:
    # 0044: any failure on the way to a HookDecision denies with its full cause.
    try:
        module = _module(hook.script, plugin_root, cache)
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return hook_io.failed_closed(hook.script, exc)
    decide = getattr(module, "decide", None)
    if not callable(decide):
        return hook_io.failed_closed(hook.script, "no decide function")
    try:
        decision = decide(hook_input, list(hook.flags))
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        return hook_io.failed_closed(hook.script, exc)
    if not isinstance(decision, hook_io.HookDecision):
        return hook_io.failed_closed(hook.script, f"decide returned {type(decision).__name__}")
    return decision.reason


def route(hook_input: dict[str, object], plugin_root: Path) -> tuple[bool, str | None, str]:
    # 0044: (allow, reason, hook name); the caller passes the plugin root, never the environment.
    name = hook_io.agent(hook_input)
    if name == "main":
        return False, R_MAIN, ROUTER
    path = plugin_root / "agents" / f"{name}.md"
    if not agent_files.AGENT_NAME.fullmatch(name) or not path.is_file():
        return False, R_NO_FILE.format(name=name), ROUTER
    try:
        agent = agent_files.load(path)
    except agent_files.AgentFileError as exc:
        return False, str(exc), ROUTER
    if not agent.hooks:
        return False, R_NO_HOOKS.format(name=name), ROUTER
    for hook in agent.hooks:
        reason = _run(hook, hook_input, plugin_root)
        if reason is not None:
            return False, reason, hook.script
    for hook in EVERY_AGENT:
        reason = _run(hook, hook_input, _OWN_ROOT, _EVERY_MODULES)
        if reason is not None:
            return False, reason, hook.script
    return True, None, ""
