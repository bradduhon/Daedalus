# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0031: operator lines name things in words; ids, paths and code trail and are not counted.
# The one word counter; the skill scanner test and train validator check 11 both import it.
from __future__ import annotations

import re

from lib.train_scope import KNOWN_AGENTS

DROP_SPANS = re.compile(r"`[^`]*`|<[^<>]*>|\{[^{}]*\}|\([^()]*\)|https?://\S+")
EDGE = ".,;:!?\"'[]"
MIN_WORDS = 4
_WORD = re.compile(r"[A-Za-z][A-Za-z'-]*")


def plain_words(text: str) -> list[str]:
    out = []
    for raw in DROP_SPANS.sub(" ", text).split():
        token = raw.strip(EDGE)
        if token in KNOWN_AGENTS or any(c in token for c in "/\\~$_:.*=@#"):
            continue
        if _WORD.fullmatch(token):
            out.append(token)
    return out
