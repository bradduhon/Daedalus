# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: .. segments and redirects that leave the unit worktree or reach a store.
from __future__ import annotations

from pathlib import Path

import pytest

from tests.adversarial.corpus import CREDENTIAL, OUTSIDE, PROTECTED, READERS, assert_denied
from tests.conftest import CWD, WT
from tests.test_jail import _b, _cred, _w, cred_home  # noqa: F401 - registers cred_home

pytestmark = pytest.mark.usefixtures("jail_fakes")
# 0022, 0054: each target resolves into the main checkout or another repository.
CODER_WRITE_PATHS = (
    "{wt}/../../../src/a.py",
    "{wt}/src/../../../../infra/a.tf",
    "{wt}/../u1/../../../service-manifest.json",
    "{cwd}/.claude/worktrees/x/../../daedalus/src/a.py",
    "{cwd}/src/../infra/a.tf",
    "{wt}/../../../../other/src/a.py",
    "{wt}/./../../../src/a.py",
    "{wt}//..//..//../src/a.py",
    "src/../src/a.py",
    ".claude/worktrees/u1/../../../src/a.py",
)
# 20261019-124612 audit: a redirect becomes a tee segment judged by the same write check.
CODER_WRITE_COMMANDS = (
    "tee {wt}/../../../src/a.py",
    "cp {wt}/README.md {wt}/../../../src/a.py",
    "mv {wt}/src/a.py {wt}/../../../src/a.py",
    "sed -i s/a/b/ {wt}/../../../src/a.py",
    "echo x > {wt}/../../../src/a.py",
    "echo x >> {wt}/../../../src/a.py",
    "ls > {wt}/../../../src/a.py",
    "echo x > ../src/a.py",
    "truncate -s 0 {wt}/../../../service-manifest.json",
    "cd {wt} && tee ../../../src/a.py",
    "cd {wt}/src && tee ../../../../infra/a.tf",
    "cd {wt} && echo x > ../../../src/a.py",
    "rsync -a {wt}/src/ {wt}/../../../src/",
    "install -m 644 {wt}/README.md {wt}/../../../src/a.py",
)
# built-in protected paths inside the worktree, reached by a .. or a doubled slash.
PROTECTED_PATHS = (
    "{wt}/src/../contracts/openapi.yaml",
    "{wt}/src/../.github/workflows/ci.yml",
    "{wt}/./service-manifest.json",
    "{wt}//contracts//x.yaml",
    "{wt}/tests/../.claude/settings.json",
)
STORE_READS = (
    "cat {home}/project/../.ssh/id_ed25519",
    "cat {home}/a/b/../../.aws/credentials",
    "cd {home}/project && cat ../.ssh/id_ed25519",
    "grep -rn key {home}/project/../.aws",
    "cat {home}/.ssh/../.ssh/id_ed25519",
    "cat {home}/./.gnupg/pubring.kbx",
)
# spec 3.7: the auditor's audit folder is never a door to the summary, the briefs or source.
AUDIT = f"{CWD}/docs/.tmp/daedalus/20261015-120000/audit"
AUDIT_ESCAPES = (
    f"{AUDIT}/../20261015-120000-summary.md",
    f"{AUDIT}/../briefs/c1.md",
    f"{AUDIT}/round1/../../briefs/c1.md",
    f"{AUDIT}/../../../../../scripts/lib/jail.py",
    f"{AUDIT}/round1/../../../../../../src/a.py",
)


@pytest.mark.parametrize("template", CODER_WRITE_PATHS)
@pytest.mark.parametrize("tool", ("Write", "Edit"))
def test_coder_write_tool_traversal_is_denied(template: str, tool: str) -> None:
    path = template.format(wt=WT, cwd=CWD)
    assert_denied(_w("repo-coder", path, tool), OUTSIDE, "plugin data directory")


@pytest.mark.parametrize("template", CODER_WRITE_COMMANDS)
def test_coder_bash_traversal_is_denied(template: str) -> None:
    assert_denied(_b("repo-coder", template.format(wt=WT)))


@pytest.mark.parametrize("template", PROTECTED_PATHS)
def test_traversal_onto_a_protected_path_is_denied(template: str) -> None:
    path = template.format(wt=WT)
    assert_denied(_w("repo-coder", path), PROTECTED)
    assert_denied(_b("repo-coder", f"tee {path}"), PROTECTED)


@pytest.mark.parametrize("agent", READERS)
@pytest.mark.parametrize("template", STORE_READS)
def test_traversal_into_a_store_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
    template: str,
) -> None:
    assert_denied(_cred(agent, "Bash", command=template.format(home=cred_home)), CREDENTIAL)


@pytest.mark.parametrize("agent", READERS)
def test_read_tool_traversal_into_a_store_is_denied(
    cred_home: Path,  # noqa: F811
    agent: str,
) -> None:
    for path in (f"{cred_home}/project/../.ssh/id_ed25519", f"{cred_home}/./.aws/credentials"):
        assert_denied(_cred(agent, "Read", file_path=path), CREDENTIAL)


@pytest.mark.parametrize("path", AUDIT_ESCAPES)
def test_auditor_write_leaving_the_audit_folder_is_denied(path: str) -> None:
    assert_denied(_cred("security-auditor", "Write", file_path=path, content="x"))
    assert_denied(_cred("security-auditor", "Bash", command=f"tee {path}"))
    assert_denied(_cred("security-auditor", "Bash", command=f"echo x > {path}"))
