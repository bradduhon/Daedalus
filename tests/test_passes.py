# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 233: the sealed one-time pass; its seal, its exact match, its single use and its audit line.
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from lib import audit, jail, passes, train_summary

from tests.adversarial.corpus import S2B_PASS_ONCE, S3B_CODER_PASS_ONCE
from tests.conftest import CFG, SCRIPTS_DIR, run_cli
from tests.helpers import phase_text
from tests.hook_chain import first_deny

AGENT = "verifier"
SESSION = "sess-pass"
REASON = "sort writes its output file"
LEDGER = "0222-DAE-PLT"
ROW = "| `[STATUS: YIELD_GRANT]"


def _run(repo: Path) -> bytes:
    # 233: an active run holds the train marker and the reply key that seals a pass.
    audit.ensure_project_data_dir(str(repo))
    return audit.reply_key(str(repo), create=True)


def _command(repo: Path) -> str:
    return S2B_PASS_ONCE[1].format(repo=repo)


def _grant(repo: Path, command: str, agent: str = AGENT, ttl: int = 300) -> Path:
    return passes.write_pass(repo, agent, command, str(repo), REASON, LEDGER, ttl)


def _hook(repo: Path, command: str, agent_type: str = "daedalus:verifier") -> dict[str, Any]:
    return {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "agent_type": agent_type,
        "agent_id": "a1",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "toolu_pass",
    }


def _consumed(repo: Path) -> list[dict[str, Any]]:
    log = audit.log_path(SESSION, str(repo))
    if not log.exists():
        return []
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if r.get("event") == passes.PASS_EVENT]


def test_happy_path_writes_consumes_once_and_records(marked_repo: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    record = passes.load(path)
    assert record is not None and record.single_use and record.agent_id == AGENT
    assert path.name == f"{passes.command_sha256(command)}.json"
    assert record.cwd == str(marked_repo) and record.ledger_id == LEDGER
    hook = _hook(marked_repo, command)
    assert passes.pass_admits(marked_repo, AGENT, command, str(marked_repo), hook)
    assert not path.exists()
    lines = [r["reason"] for r in _consumed(marked_repo)]
    digest = passes.command_sha256(command)[:12]
    assert lines == [f"pass consumed agent={AGENT} sha256={digest} reason={REASON}"]
    assert not passes.pass_admits(marked_repo, AGENT, command, str(marked_repo), hook)


def test_the_pass_digest_is_the_refusal_digest(marked_repo: Path) -> None:
    command = _command(marked_repo)
    refused = jail._refused(jail._admission(command, AGENT, str(marked_repo))[1])
    assert refused is not None and refused.sha256 == passes.command_sha256(command)


def _hunts(repo: Path, command: str, other: Path) -> dict[str, tuple[str, str, str]]:
    # 233: each form differs from the granted call in one thing; (agent, command, cwd).
    here = str(repo)
    return {
        "one byte": (AGENT, command + " ", here),
        "one byte inside": (AGENT, command.replace("out.txt", "out.txu"), here),
        "another agent": ("auditor", command, here),
        "namespaced agent": ("daedalus:verifier", command, here),
        "another folder": (AGENT, command, str(other)),
        "a subfolder": (AGENT, command, f"{here}/src"),
        "quotes added": (AGENT, command.replace("sort -o", "sort '-o'"), here),
        "whitespace doubled": (AGENT, command.replace("sort -o", "sort  -o"), here),
        "tab for space": (AGENT, command.replace("sort -o", "sort\t-o"), here),
        "relative folder": (AGENT, command, "repo"),
        "empty command": (AGENT, "", here),
    }


HUNT_NAMES = (
    "one byte",
    "one byte inside",
    "another agent",
    "namespaced agent",
    "another folder",
    "a subfolder",
    "quotes added",
    "whitespace doubled",
    "tab for space",
    "relative folder",
    "empty command",
)


@pytest.mark.parametrize("name", HUNT_NAMES)
def test_a_mismatched_call_refuses_and_leaves_the_pass(
    marked_repo: Path, other_repo: Path, name: str
) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    before = path.read_bytes()
    agent, text, cwd = _hunts(marked_repo, command, other_repo)[name]
    assert passes.consume_pass(marked_repo, agent, text, cwd) is None
    assert path.read_bytes() == before
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is not None


def test_the_hunt_table_names_every_form(marked_repo: Path, other_repo: Path) -> None:
    assert tuple(_hunts(marked_repo, "x", other_repo)) == HUNT_NAMES


def test_a_second_use_refuses(marked_repo: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    _grant(marked_repo, command)
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is not None
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None


class _Later(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> _Later:
        moved = datetime.now(tz) + timedelta(seconds=301)
        return cls.fromtimestamp(moved.timestamp(), tz)


def test_an_expired_pass_is_deleted_and_refuses(
    marked_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    monkeypatch.setattr(passes, "datetime", _Later)
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
    assert not path.exists()


def test_an_expired_pass_for_another_agent_is_deleted_too(
    marked_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command, agent="auditor")
    monkeypatch.setattr(passes, "datetime", _Later)
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
    assert not path.exists()


def _rewrite(path: Path, **fields: object) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(fields)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize(
    "fields",
    [
        {"seal": "0" * 64},
        {"seal": ""},
        {"agent_id": "auditor"},
        {"cwd": "/"},
        {"reason": "another reason"},
        {"expires": "2999-01-01T00:00:00+00:00"},
        {"single_use": False},
        {"ledger_id": "0001-DAE-PLT"},
    ],
)
def test_a_bad_seal_refuses_and_leaves_the_file(
    marked_repo: Path, fields: dict[str, object]
) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    _rewrite(path, **fields)
    before = path.read_bytes()
    agent = str(fields.get("agent_id", AGENT))
    cwd = str(fields.get("cwd", marked_repo))
    assert passes.consume_pass(marked_repo, agent, command, cwd) is None
    assert path.read_bytes() == before


def test_a_pass_sealed_with_a_wrong_key_refuses(marked_repo: Path) -> None:
    # 233: an agent holds no key, so the best it can write is a seal under a key of its own.
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["seal"]
    forged = passes._seal(b"k" * 32, data)
    _rewrite(path, seal=forged)
    before = path.read_bytes()
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
    assert path.read_bytes() == before


def test_an_unsealed_or_extra_field_pass_refuses(marked_repo: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    data = json.loads(path.read_text(encoding="utf-8"))
    for body in ({k: v for k, v in data.items() if k != "seal"}, {**data, "extra": "x"}):
        path.write_text(json.dumps(body), encoding="utf-8")
        assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
        assert path.exists()


def test_a_linked_pass_file_refuses(marked_repo: Path, tmp_path: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    target = tmp_path / "pass.json"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
    assert path.is_symlink()


def test_a_pass_written_in_another_repo_refuses(marked_repo: Path, tmp_path: Path) -> None:
    # 233: each repository's reply key seals only its own passes.
    other = tmp_path.resolve() / "second"
    other.mkdir()
    from tests.conftest import git, write_train_marker

    git(other, "init", "-q", "-b", "main")
    write_train_marker(other)
    _run(marked_repo)
    _run(other)
    command = _command(marked_repo)
    path = passes.write_pass(other, AGENT, command, str(marked_repo), REASON, LEDGER)
    target = passes._grants_dir(marked_repo) / path.name
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.write_bytes(path.read_bytes())
    assert passes.consume_pass(marked_repo, AGENT, command, str(marked_repo)) is None
    assert target.exists()


def test_write_pass_refuses_without_an_active_run(repo_cwd: Path) -> None:
    with pytest.raises(passes.PassError, match="no run is active"):
        _grant(repo_cwd, "sort -o x y")


def test_write_pass_refuses_without_a_reply_key(marked_repo: Path) -> None:
    with pytest.raises(passes.PassError, match="no reply key"):
        _grant(marked_repo, "sort -o x y")


def test_write_pass_refuses_an_empty_command_and_a_live_pass(marked_repo: Path) -> None:
    _run(marked_repo)
    for empty in ("", "  \n"):
        with pytest.raises(passes.PassError, match="empty"):
            _grant(marked_repo, empty)
    _grant(marked_repo, "sort -o x y")
    with pytest.raises(passes.PassError, match="a pass for this command exists"):
        _grant(marked_repo, "sort -o x y")


def test_write_pass_replaces_an_expired_pass(
    marked_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(marked_repo)
    _grant(marked_repo, "sort -o x y")
    monkeypatch.setattr(passes, "datetime", _Later)
    path = _grant(marked_repo, "sort -o x y")
    assert path.exists()


def test_pass_admits_refuses_once_the_run_ended(marked_repo: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    path = _grant(marked_repo, command)
    (marked_repo / ".claude" / "daedalus" / "train.active").unlink()
    hook = _hook(marked_repo, command)
    assert not passes.pass_admits(marked_repo, AGENT, command, str(marked_repo), hook)
    assert path.exists()


def _grant_cli(repo: Path, command_file: Path) -> list[str]:
    return [
        "grant",
        "--repo",
        str(repo),
        "--agent",
        AGENT,
        "--cwd",
        str(repo),
        "--reason",
        REASON,
        "--ledger-id",
        LEDGER,
        "--command-file",
        str(command_file),
    ]


def test_grant_refuses_without_an_active_run(repo_cwd: Path, tmp_path: Path) -> None:
    file = tmp_path / "command.txt"
    file.write_text("sort -o x y", encoding="utf-8")
    done = run_cli("daedalus_train.py", *_grant_cli(repo_cwd, file), cwd=repo_cwd)
    assert done.returncode == 1, done.stdout
    assert "no run is active" in done.stdout
    assert not (repo_cwd / ".claude" / "daedalus" / passes.GRANTS).exists()


def test_grant_reads_the_command_from_its_file_exactly(marked_repo: Path, tmp_path: Path) -> None:
    _run(marked_repo)
    command = _command(marked_repo)
    file = tmp_path / "command.txt"
    file.write_bytes(command.encode("utf-8"))
    done = run_cli("daedalus_train.py", *_grant_cli(marked_repo, file), cwd=marked_repo)
    assert done.returncode == 0, done.stdout
    digest = passes.command_sha256(command)
    line = done.stdout.strip()
    assert line.startswith(f"pass written sha256={digest[:12]} expires=20"), line
    path = passes._grants_dir(marked_repo) / f"{digest}.json"
    record = passes.load(path)
    assert record is not None and line.endswith(f"expires={record.expires}")


def test_grant_runs_for_the_main_session_only(marked_repo: Path) -> None:
    # 233: as the exception record, the orchestrator's train rows never name grant.
    command = (
        f"python3 {SCRIPTS_DIR}/daedalus_train.py grant --repo {marked_repo} --agent coder "
        f"--cwd {marked_repo} --reason r --ledger-id {LEDGER} --command-file {marked_repo}/c.txt"
    )
    assert jail.admitted(command, "main", str(marked_repo))
    assert not jail.admitted(command, "orchestrator", str(marked_repo))


def _verifier(repo: Path, command: str) -> tuple[str, str] | None:
    return first_deny(_hook(repo, command), CFG)


def test_corpus_row_a_routed_agent_is_admitted_exactly_once(marked_repo: Path) -> None:
    # 233: refused, admitted once with a pass, refused again; the read_only_bash seam.
    agent, form = S2B_PASS_ONCE
    command = form.format(repo=marked_repo)
    _run(marked_repo)
    assert (_verifier(marked_repo, command) or ("",))[0] == "read_only_bash"
    _grant(marked_repo, command, agent=agent)
    assert _verifier(marked_repo, command) is None
    assert (_verifier(marked_repo, command) or ("",))[0] == "read_only_bash"
    assert len(_consumed(marked_repo)) == 1


def test_corpus_row_a_foreign_agent_is_admitted_exactly_once(marked_repo: Path) -> None:
    # 233: the _foreign_bash seam; the pass names the agent type as the hook input carries it.
    command = S2B_PASS_ONCE[1].format(repo=marked_repo)
    _run(marked_repo)
    hook = _hook(marked_repo, command, agent_type="Explore")
    assert not jail.decide(hook, CFG).allow
    _grant(marked_repo, command, agent="Explore")
    assert jail.decide(hook, CFG).allow
    refused = jail.decide(hook, CFG)
    assert not refused.allow and "read-only while" in str(refused.reason)
    assert len(_consumed(marked_repo)) == 1


def test_the_build_phase_routes_a_grant_yield() -> None:
    rows = (ln.strip() for ln in phase_text("build").splitlines())
    row = next(ln for ln in rows if ln.startswith(ROW))
    assert row.startswith("| `[STATUS: YIELD_GRANT] <exact command> \\| <why>` |")
    for part in ("`Grant once`", "`Refuse`", "`Add a table row instead`"):
        assert part in row, part
    assert (
        "`python3 <plugin root>/scripts/daedalus_train.py grant --repo <repo> --agent coder "
        '--cwd <repo> --reason "<why>" --ledger-id <ID> --command-file <that file>`'
    ) in row
    # 228 S3b: the coder's hook calls carry the main checkout, so the pass is sealed to it.
    assert (
        "`--cwd` is the main checkout because the coder's shell starts there and its hook calls "
        "carry that folder."
    ) in row
    assert "The orchestrator never runs it." in row
    assert "`pass written sha256=<12 hex> expires=<timestamp>`" in row
    assert 'SendMessage(coder, "Run the exact command again.")' in row
    assert (
        "`Friction: <agent>, table gap, <command word and option> granted once (pass <12 hex>)` "
        "under `## Blocks` in the summary notes file"
    ) in row
    assert "per-finding prompt shape" in row


def test_the_coder_yields_a_grant_never_a_workaround() -> None:
    text = (SCRIPTS_DIR.parent / "agents" / "coder.md").read_text(encoding="utf-8")
    contract = text.split("## Status contract", 1)[1]
    assert "- `[STATUS: YIELD_GRANT] <exact command> | <why>`\n" in contract
    ask = text.split("## Build only the ask (227)", 1)[1].split("\n## ", 1)[0]
    assert (
        "- A jail refusal on a form your work legitimately needs is a `YIELD_GRANT`, never a "
        "workaround: commit WIP and return `[STATUS: YIELD_GRANT] <exact command> | <why>` (233)."
    ) in ask


def test_corpus_row_an_allowlist_agent_is_admitted_exactly_once(marked_repo: Path) -> None:
    # 233: the command_allowlist seam, with the orchestrator's train and inspect classes.
    command = S2B_PASS_ONCE[1].format(repo=marked_repo)
    _run(marked_repo)
    hook = _hook(marked_repo, command, agent_type="daedalus:orchestrator")
    assert first_deny(hook, CFG) is not None
    _grant(marked_repo, command, agent="orchestrator")
    # 228 tail: the pass admits the grammar's refusal once; the typed sort -o write still meets
    # root_writes, which the old chain parser never read as a write.
    after = first_deny(hook, CFG)
    assert after is not None and after[0] == "root_writes", after
    denied = first_deny(hook, CFG)
    assert denied is not None and denied[0] == "command_allowlist", denied
    assert len(_consumed(marked_repo)) == 1


def _coder(repo: Path, command: str) -> tuple[str, str] | None:
    # 228 S3b: a fresh payload per call, as the router hands each hook call its own.
    return first_deny(_hook(repo, command, agent_type="daedalus:coder"), CFG)


def test_corpus_row_a_coder_write_is_admitted_exactly_once(marked_repo: Path) -> None:
    # 233, 228 S3b: all four coder checks share one pass; refused, admitted once, refused again.
    agent, form = S3B_CODER_PASS_ONCE
    command = form.format(repo=marked_repo)
    _run(marked_repo)
    first = _coder(marked_repo, command)
    assert first is not None and first[0] == "shell_tripwires", first
    assert "Refused: perl is not on the coder command table" in first[1]
    _grant(marked_repo, command, agent=agent)
    assert _coder(marked_repo, command) is None
    again = _coder(marked_repo, command)
    assert again is not None and again[0] == "shell_tripwires", again
    assert len(_consumed(marked_repo)) == 1


def test_a_coder_pass_admits_only_its_folder(marked_repo: Path) -> None:
    # 233, 228 S3b: the pass is sealed to the main checkout the coder's hook calls carry.
    command = S3B_CODER_PASS_ONCE[1].format(repo=marked_repo)
    _run(marked_repo)
    _grant(marked_repo, command, agent="coder")
    moved = _hook(marked_repo, command, agent_type="daedalus:coder")
    moved["cwd"] = str(marked_repo / ".claude")
    assert first_deny(moved, CFG) is not None
    assert _coder(marked_repo, command) is None


def test_a_grant_yield_names_the_main_session_as_its_answerer() -> None:
    # 233, 228 S3b: the main session asks the operator and writes the pass.
    assert train_summary._ANSWERERS["YIELD_GRANT"] == (train_summary.MAIN_SESSION,)
    asked = train_summary._YIELD.match("[STATUS: YIELD_GRANT] sed -i x | the fix needs it")
    assert asked is not None
    reply = train_summary.Reply(seq=1, agent="coder", agent_id="c1", text=asked.group(0))
    row = train_summary._yield_row([], [reply], reply, asked, [])
    assert row == ("", "YIELD_GRANT", "sed -i x | the fix needs it", "main session")
