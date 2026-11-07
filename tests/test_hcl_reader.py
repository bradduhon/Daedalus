# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0212: the built-in Terraform reader and the guidance that sends finding tests to it.
from __future__ import annotations

import pytest
from lib.hcl_reader import (
    MAX_DEPTH,
    Block,
    HclError,
    list_parts,
    list_value,
    parse,
    policy_statements,
    require_literal,
    string_value,
    substitute,
)

from tests.conftest import REPO_ROOT

POLICY = (REPO_ROOT / "tests" / "fixtures" / "hcl" / "policy.hcl").read_text(encoding="utf-8")

HEREDOC = (
    'resource "aws_iam_policy" "p" {\n'
    "  policy = <<-EOT\n"
    "    {\n"
    '      "Statement": [{"Action": "${var.action}", "Resource": "*"}]\n'
    "    }\n"
    "    EOT\n"
    '  name = "p"\n'
    "}\n"
)


def test_parse_keeps_attributes_as_source_and_dynamic_blocks() -> None:
    blocks = parse(POLICY)
    assert [(b.type, b.labels) for b in blocks] == [
        ("data", ("aws_iam_policy_document", "read")),
        ("data", ("aws_iam_policy_document", "other")),
    ]
    dynamic = blocks[0].blocks[1]
    assert (dynamic.type, dynamic.labels, dynamic.attributes) == (
        "dynamic",
        ("statement",),
        {"for_each": "var.extra"},
    )
    assert [b.type for b in dynamic.blocks] == ["content"]
    assert blocks[0].blocks[0].attributes["effect"] == '"Allow"'


def test_condition_values_keep_interpolations_intact() -> None:
    first = policy_statements(parse(POLICY), name="read")[0]
    assert (first.sid, first.effect, first.dynamic) == ("ReadOwnPrefix", "Allow", False)
    assert first.actions == ("s3:GetObject", "s3:ListBucket")
    assert (first.resources, first.unresolved_resources) == (
        (),
        ('"arn:aws:s3:::${var.bucket}/${lookup(local.m, "k", "}")}/*"',),
    )
    assert [(p.type, p.identifiers, p.unresolved_identifiers) for p in first.principals] == [
        ("AWS", (), ("aws_iam_role.app.arn",))
    ]
    (cond,) = first.conditions
    assert (cond.test, cond.variable) == ("StringLike", "s3:prefix")
    assert cond.values == ("home/$${aws:username}/*",)
    assert cond.unresolved_values == ('"${var.env}-%{ if var.x }a%{ endif }"',)
    assert [f for f, _ in first.unresolved_fields()] == [
        "resources",
        "principals.identifiers",
        "condition.values",
    ]


def test_dynamic_statement_is_returned_and_marked() -> None:
    found = policy_statements(parse(POLICY))
    assert [(s.document, s.dynamic) for s in found] == [
        ("read", False),
        ("read", True),
        ("other", False),
    ]
    dyn = found[1]
    assert (dyn.actions, dyn.unresolved_actions) == ((), ("statement.value.actions",))
    assert dyn.resources == ("*",)
    (cond,) = dyn.conditions
    assert cond.dynamic and cond.unresolved_values == ("condition.value.account",)
    assert cond.variable == "aws:SourceAccount" and cond.test == "condition.value.test"
    assert found[2].not_actions == ("iam:*",)
    assert found[2].not_resources == ("arn:aws:iam::*:role/x",)


@pytest.mark.parametrize("marker", ["<<-EOT", "<<EOT"])
def test_heredoc_policy_is_returned_verbatim(marker: str) -> None:
    text = HEREDOC.replace("<<-EOT", marker)
    (block,) = parse(text)
    start = text.index(marker)
    assert block.attributes["policy"] == text[start : text.index("EOT\n", start + 6) + 3]
    assert block.attributes["policy"].startswith(marker + "\n    {")
    assert block.attributes["name"] == '"p"'


def test_substitute_replaces_only_mapped_names() -> None:
    value = "arn:${var.a}:${ var.b }:$${aws:username}:%{ if var.a }x%{ endif }:${var.c}"
    assert substitute(value, {"var.a": "A", "var.b": "B"}) == (
        "arn:A:B:$${aws:username}:%{ if var.a }x%{ endif }:${var.c}"
    )


@pytest.mark.parametrize(
    ("source", "literals", "unresolved"),
    [
        ('["a", "b",]', ("a", "b"), ()),
        ('["x\\"y", "\\u0041"]', ('x"y', "A"), ()),
        ('["$${aws:username}"]', ("$${aws:username}",), ()),
        ("var.list", (), ("var.list",)),
        ('concat(["a"], var.b)', (), ('concat(["a"], var.b)',)),
        ("[for s in var.l : s]", (), ("[for s in var.l : s]",)),
        ("[var.a, 3]", (), ("var.a", "3")),
        ('["s3:Get", local.x, "${var.y}"]', ("s3:Get",), ("local.x", '"${var.y}"')),
    ],
)
def test_list_parts_split_literals_from_unresolved(
    source: str, literals: tuple[str, ...], unresolved: tuple[str, ...]
) -> None:
    assert list_parts(source) == (literals, unresolved)
    if unresolved:
        with pytest.raises(HclError, match="^line 1: list item is not a literal"):
            list_value(source)
    else:
        assert list_value(source) == literals


# 0212: the audit round 1 cases; a non-literal actions value never reads as a narrow list.
@pytest.mark.parametrize(
    ("actions", "unresolved"),
    [
        ("local.all", ("local.all",)),
        ('concat(["s3:GetObject"], ["*"])', ('concat(["s3:GetObject"], ["*"])',)),
        ('["s3:Get", local.x]', ("local.x",)),
        ('["s3:GetObject"]', ()),
    ],
)
def test_require_literal_fails_closed_on_unresolved_actions(
    actions: str, unresolved: tuple[str, ...]
) -> None:
    text = (
        'data "aws_iam_policy_document" "p" {\n  statement {\n    effect = "Allow"\n'
        f'    actions = {actions}\n    resources = ["arn:aws:s3:::b/*"]\n  }}\n}}\n'
    )
    (stmt,) = policy_statements(parse(text))
    assert stmt.unresolved_actions == unresolved
    assert set(stmt.actions) <= {"s3:Get", "s3:GetObject"}
    assert stmt.has_unresolved is bool(unresolved)
    if unresolved:
        with pytest.raises(HclError, match="^line 2: actions of statement p is not a literal"):
            require_literal(stmt)
    else:
        assert require_literal(stmt) is stmt
    with pytest.raises(HclError, match="^line 1: expected a Statement"):
        require_literal(text)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "source",
    [
        '"s3:GetObject"',
        "5",
        "true",
        "null",
        '{ a = "b" }',
        '[["a"]]',
        '["a", ["b"]]',
        "[{}]",
        '["a",,]',
        "<<EOT\nx\nEOT",
    ],
)
def test_wrong_types_and_nested_lists_raise(source: str) -> None:
    with pytest.raises(HclError):
        list_value(source)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (None, "parse"),
        (b"data {}", "parse"),
        (5, "parse"),
        (["x"], "parse"),
        ("x", "substitute"),
        (["x"], "statements"),
    ],
)
def test_wrong_input_types_raise_hcl_error(value: object, kind: str) -> None:
    with pytest.raises(HclError, match=r"^line \d+: "):
        if kind == "parse":
            parse(value)  # type: ignore[arg-type]
        elif kind == "substitute":
            substitute(value, {"a": 1})  # type: ignore[arg-type, dict-item]
        else:
            policy_statements(value)  # type: ignore[arg-type]


def test_statement_wrong_types_raise() -> None:
    text = 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = "s3:*"\n  }\n}\n'
    with pytest.raises(HclError, match="^line 3: expected a list"):
        policy_statements(parse(text))
    assert string_value('"a${b}"') == "a${b}"
    with pytest.raises(HclError):
        string_value("var.a")


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ('a "b" {\n  x = "open\n}\n', 2),
        ('a {\n  x = "${var.y\n}\n', 2),
        ('a {\n  x = "${ "q }"\n}\n', 2),
        ("a {\n  x = <<EOT\n  body\n}\n", 2),
        ("a {\n  /* never closed\n}\n", 2),
        ("a {\n  x = 1\n", 1),
        ("a {\n  x = [1, 2\n}\n", 3),
        ("a {\n  x = 1\n}\n}\n", 4),
        ("x = 1\n", 1),
        ("a {\n  x =\n}\n", 2),
        ("a {\n  x = 1\n  x = 2\n}\n", 3),
        ('a "${b}" {\n}\n', 1),
        ("a { } b\n", 1),
        ("a {\n  x = @\n}\n", 2),
        ('a {\n  x = "\\q"\n}\n', 2),
        ('a {\n\n  x = "\\U00110000"\n}\n', 3),
        ("a {\n  x = << EOT\n}\n", 2),
    ],
)
def test_malformed_input_raises_naming_the_line(text: str, line: int) -> None:
    with pytest.raises(HclError, match=f"^line {line}: ") as caught:
        parse(text)
    assert caught.value.line == line


@pytest.mark.parametrize(
    "text",
    [
        "a {\n" * (MAX_DEPTH + 1) + "}\n" * (MAX_DEPTH + 1),
        "a {\n  x = " + "[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1) + "\n}\n",
        'a {\n  x = "' + '${"' * MAX_DEPTH + '"}' * MAX_DEPTH + '"\n}\n',
    ],
)
def test_nesting_past_max_depth_raises(text: str) -> None:
    with pytest.raises(HclError, match=f"MAX_DEPTH={MAX_DEPTH}"):
        parse(text)


def test_nesting_at_the_cap_parses() -> None:
    depth = MAX_DEPTH
    blocks = parse("a {\n" * depth + "}\n" * depth)
    inner: Block = blocks[0]
    for _ in range(depth - 1):
        inner = inner.blocks[0]
    assert inner.blocks == ()


@pytest.mark.parametrize(
    "path", ["skills/audit/SKILL.md", "agents/auditor.md", "agents/verifier.md"]
)
def test_guidance_names_the_reader_and_bans_regex(path: str) -> None:
    text = " ".join((REPO_ROOT / path).read_text(encoding="utf-8").split())
    assert "imports `lib.hcl_reader`" in text
    assert "`<plugin root>/scripts`" in text
    assert "Never extract HCL blocks with a regex" in text
    assert "(0212)" in text
    assert "calls `require_literal` on each statement, or fails when `has_unresolved`" in text


def test_audit_skill_bullet_sits_under_step_five() -> None:
    text = (REPO_ROOT / "skills/audit/SKILL.md").read_text(encoding="utf-8")
    step = text.split("\n5. Dispatch `auditor`", 1)[1].split("\n### Short form", 1)[0]
    assert "\n   - Finding tests on Terraform files (0212)." in step


def test_auditor_guidance_sits_in_finding_format_item_one() -> None:
    text = (REPO_ROOT / "agents/auditor.md").read_text(encoding="utf-8")
    item = " ".join(
        text.split("1. **One test per blocking finding**", 1)[1].split("\n2. **", 1)[0].split()
    )
    assert "`lib.hcl_reader`" in item and "Never extract HCL blocks with a regex" in item
