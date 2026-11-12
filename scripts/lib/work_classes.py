# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0267, 0270, 0280: the classes of work and the model each runs on; the shipped defaults, the
# checks of the two personal settings and the one lookup of a class's model.
from __future__ import annotations

from typing import TYPE_CHECKING

from lib.agent_models import MODELS
from lib.user_keys import is_user_key, unknown_keys, without_user_keys

if TYPE_CHECKING:
    from lib.operator_file import Operator

TOP_MODEL, MIDDLE_MODEL, SMALLEST_MODEL = "opus", "sonnet", "haiku"
NAME_MAX, DEFINITION_MAX, MAX_CLASSES = 40, 300, 64
ROW_KEYS = ("name", "definition")
ORDINARY, MECHANICAL = "Ordinary work", "Mechanical work"
_BUILDS = "The work builds or changes "
# 0280: every name and definition fits a document or an investigation as well as code.
DEFAULT_CLASSES: tuple[tuple[str, str], ...] = (
    (
        "AuthN",
        _BUILDS + "how a caller's identity is proven: login, sessions, MFA, SSO, OIDC or "
        "SAML flows.",
    ),
    (
        "AuthZ",
        _BUILDS + "what a caller may do: permission checks, role or attribute rules, policy "
        "evaluation, tenant isolation.",
    ),
    (
        "Identity",
        _BUILDS + "the record of who a principal is: user and service accounts, identity "
        "providers and federation, how identities are created, linked or removed.",
    ),
    (
        "Access grants and escalation",
        _BUILDS + "who holds access: IAM policies, roles, trust policies, role assumption, "
        "admin elevation, sharing and ACL changes.",
    ),
    (
        "Cryptography",
        _BUILDS + "signing, verifying, hashing for security, key derivation, secure "
        "randomness, certificate validation, TLS settings.",
    ),
    (
        "Encryption",
        _BUILDS + "encrypting or decrypting data at rest or in transit: key choice, key "
        "service use, envelope encryption.",
    ),
    (
        "Secrets",
        _BUILDS + "creating, storing, rotating, reading or sending a secret; the secret store "
        "itself.",
    ),
    ("Tokens", _BUILDS + "issuing, signing, validating, refreshing or revoking a token."),
    ("API keys", _BUILDS + "issuing, storing, validating, scoping or rotating an API key."),
    ("Credentials", _BUILDS + "storing, comparing or resetting credentials; credential files."),
    ("Untrusted input", _BUILDS + "the first parse or check of input from outside the system."),
    (
        "Network exposure",
        _BUILDS + "what is reachable and from where: firewall rules, security groups, public "
        "endpoints, CORS.",
    ),
    ("Audit trail", _BUILDS + "the security log itself and what keeps it tamper-evident."),
    (
        "Security rules",
        _BUILDS + "the rules a security scanner or guard enforces, the scanner's "
        "configuration, and any exception to or skip of a rule.",
    ),
    (ORDINARY, _BUILDS + "none of the things another class names."),
    (MECHANICAL, "The work needs no judgement: a rename, a move, a copy or a format pass."),
)
DEFAULT_MODELS: tuple[tuple[str, str], ...] = (
    *((name, TOP_MODEL) for name, _ in DEFAULT_CLASSES if name not in (ORDINARY, MECHANICAL)),
    (ORDINARY, MIDDLE_MODEL),
    (MECHANICAL, SMALLEST_MODEL),
)


def _name_ok(value: object) -> bool:
    # 0260: a name starting with an underscore would be a user key in the mapping object.
    return (
        isinstance(value, str)
        and 1 <= len(value) <= NAME_MAX
        and value.isprintable()
        and value == value.strip()
        and not is_user_key(value)
    )


def parse_classes(value: object) -> tuple[tuple[str, str], ...]:
    """0270: the classes list as (name, definition) rows; ValueError names what is wrong."""
    if not isinstance(value, list) or len(value) > MAX_CLASSES:
        raise ValueError(f"must be a list of at most {MAX_CLASSES} objects")
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"entry {index} must be an object with a name and a definition")
        unknown = unknown_keys(item, ROW_KEYS)
        if unknown:
            raise ValueError(f"entry {index} has unknown keys {unknown} (known: name, definition)")
        row = without_user_keys(item)
        name, definition = row.get("name"), row.get("definition")
        if not _name_ok(name):
            raise ValueError(
                f"entry {index} name must be one printable line of 1 to {NAME_MAX} characters, "
                "with no space at either end and not starting with an underscore"
            )
        assert isinstance(name, str)
        if name.casefold() in seen:
            raise ValueError(f"names the class {name!r} twice")
        seen.add(name.casefold())
        if not (
            isinstance(definition, str)
            and 1 <= len(definition) <= DEFINITION_MAX
            and definition.isprintable()
        ):
            raise ValueError(
                f"entry {index} definition must be one printable line of 1 to "
                f"{DEFINITION_MAX} characters"
            )
        rows.append((name, definition))
    return tuple(rows)


def parse_models(value: object) -> tuple[tuple[str, str], ...]:
    """0270: the mapping as (class name, model) pairs; the model set is the agents' own."""
    if not isinstance(value, dict) or len(value) > MAX_CLASSES:
        raise ValueError(f"must be an object of at most {MAX_CLASSES} class names")
    pairs: list[tuple[str, str]] = []
    for name, model in without_user_keys(value).items():
        if not _name_ok(name):
            raise ValueError(f"names {name!r}, which is not a class name")
        if model not in MODELS:
            raise ValueError(f"maps {name!r} to {model!r}, not one of {', '.join(MODELS)}")
        assert isinstance(model, str)
        pairs.append((name, model))
    return tuple(pairs)


def unlisted(
    classes: tuple[tuple[str, str], ...], models: tuple[tuple[str, str], ...]
) -> list[str]:
    # 0270: the mapped class names the list does not hold; the settings check refuses them.
    names = {name for name, _ in classes}
    return [name for name, _ in models if name not in names]


def model_for(name: str, operator: Operator) -> str:
    """0270: the model for one class; no classes, an unlisted class or no mapping is middle."""
    if name not in {row[0] for row in operator.work_classes}:
        return MIDDLE_MODEL
    return dict(operator.class_models).get(name, MIDDLE_MODEL)


def classes_json(rows: tuple[tuple[str, str], ...] = DEFAULT_CLASSES) -> list[dict[str, str]]:
    return [{"name": name, "definition": definition} for name, definition in rows]


def models_json(pairs: tuple[tuple[str, str], ...] = DEFAULT_MODELS) -> dict[str, str]:
    return dict(pairs)
