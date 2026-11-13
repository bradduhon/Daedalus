# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0245: the one command that rewrites the README key table from reference_table().
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from lib.project_keys import reference_table  # noqa: E402

BEGIN = "<!-- key reference -->"
END = "<!-- end key reference -->"
REGENERATE_COMMAND = "python3 tests/regen_key_table.py"


def write_readme_table(readme: Path) -> bool:
    """Rewrite the table between the markers; True when the file changed."""
    text = readme.read_text(encoding="utf-8")
    head, rest = text.split(BEGIN, 1)
    tail = rest.split(END, 1)[1]
    new = f"{head}{BEGIN}\n{reference_table()}{END}{tail}"
    if new == text:
        return False
    readme.write_text(new, encoding="utf-8")
    return True


if __name__ == "__main__":
    changed = write_readme_table(REPO_ROOT / "README.md")
    print("README.md: " + ("rewritten" if changed else "already current"))
