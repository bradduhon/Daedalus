# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import pytest
from lib.redact import redact, redact_text


@pytest.mark.parametrize(
    ("url", "masked"),
    [
        ("https://brad:s3cret@github.com/x/y.git", "https://***@github.com/x/y.git"),
        ("https://oauth2:glpat-AbC@gitlab.com/x", "https://***@gitlab.com/x"),
        ("https://x-access-token:ghs_1@github.com/o/r", "https://***@github.com/o/r"),
        ("ssh://git@github.com/o/r", "ssh://***@github.com/o/r"),
        ("https://github.com/o/r.git", "https://github.com/o/r.git"),
        ("https://a:p@ss@h/x", "https://***@h/x"),
    ],
)
def test_url_userinfo_is_masked(url: str, masked: str) -> None:
    # F5: a remote URL may carry a token in its userinfo.
    assert redact_text(f"origin {url} (fetch)") == f"origin {masked} (fetch)"


def test_url_mask_does_not_cross_quotes() -> None:
    text = '{"url":"https://h","user":"bob@example.com"}'
    assert redact_text(text) == text


def test_url_mask_does_not_cross_single_quotes() -> None:
    text = "{'url':'https://h','user':'bob@example.com'}"
    assert redact_text(text) == text


def test_aws_access_key_is_masked() -> None:
    assert redact_text("key AKIAABCDEFGHIJKLMNOP end") == "key [REDACTED_AWS_KEY] end"


def test_jwt_is_masked() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv"
    assert redact_text(f"Bearer {jwt}") == "Bearer [REDACTED_JWT]"


def test_gh_token_and_sk_key_are_masked() -> None:
    assert "[REDACTED_GH_TOKEN]" in redact_text("ghp_" + "a" * 36)
    assert "[REDACTED_API_KEY]" in redact_text("sk-" + "b" * 32)


def test_private_key_block_is_masked() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    assert redact_text(pem) == "[REDACTED_PRIVATE_KEY]"


def test_password_assignment_keeps_key_masks_value() -> None:
    assert redact_text("password=hunter2 x") == "password=[REDACTED] x"
    assert redact_text('"token": "abc123"') == '"token": "[REDACTED]"'


def test_redact_recurses_structures_and_leaves_numbers() -> None:
    value = {"a": ["AKIAABCDEFGHIJKLMNOP", 7], "b": {"c": None}}
    assert redact(value) == {"a": ["[REDACTED_AWS_KEY]", 7], "b": {"c": None}}


def test_dict_key_context_masks_value() -> None:
    assert redact({"password": "hunter2"}) == {"password": "[REDACTED]"}
    assert redact({"Authorization": "Bearer opaque"}) == {"Authorization": "[REDACTED]"}
    assert redact({"name": "x"}) == {"name": "x"}


def test_env_var_and_snake_case_names_are_masked() -> None:
    assert redact_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI") == "AWS_SECRET_ACCESS_KEY=[REDACTED]"
    snake = "aws_secret_access_key = wJalrXUtnFEMI"
    assert redact_text(snake) == "aws_secret_access_key = [REDACTED]"
    assert redact_text("GITHUB_TOKEN=abc123opaque") == "GITHUB_TOKEN=[REDACTED]"
    assert redact_text("secret_key=abc123") == "secret_key=[REDACTED]"
    assert redact_text("export TOKEN=abc123") == "export TOKEN=[REDACTED]"


def test_bearer_credential_is_masked_not_scheme() -> None:
    assert (
        redact_text("Authorization: Bearer abcdefOPAQUE123x") == "Authorization: Bearer [REDACTED]"
    )
    assert redact_text("Authorization: Basic dXNlcjpwYXNz") == "Authorization: Basic [REDACTED]"


def test_truncated_private_key_block_is_masked() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"
    assert redact_text(pem) == "[REDACTED_PRIVATE_KEY]"


def test_quoted_values_with_spaces_are_fully_masked() -> None:
    assert redact_text('password="hunter 2" x') == 'password="[REDACTED]" x'
    assert redact_text('"token": "a b c"') == '"token": "[REDACTED]"'


def test_unterminated_quoted_values_are_masked() -> None:
    assert redact_text('password="hunter2') == 'password="[REDACTED]'
    assert redact_text('"token": "abc12') == '"token": "[REDACTED]'


def test_bearer_rule_ignores_plain_english() -> None:
    assert redact_text("a basic test") == "a basic test"
    assert redact_text("Bearer abcdefOPAQUE123x") == "Bearer [REDACTED]"
