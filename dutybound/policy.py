from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from dutybound.models import Effect, EffectKind
from dutybound.patterns import PatternError, matches_any, normalize_pattern


class AuthorizationError(ValueError):
    pass


class AuthorizationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    EXHAUSTED = "EXHAUSTED"


@dataclass(frozen=True)
class Authorization:
    authorization_id: str
    objective: str
    declared_actor: str | None
    allow_paths: tuple[str, ...]
    deny_paths: tuple[str, ...]
    allowed_operations: frozenset[EffectKind]
    max_effects: int
    expires_at: datetime
    status: AuthorizationStatus
    observation_exclude: tuple[str, ...]
    source_path: Path
    source_sha256: str

    def preflight_error(self, now: datetime) -> str | None:
        if self.status is not AuthorizationStatus.ACTIVE:
            return f"authorization status is {self.status.value}, not ACTIVE"
        if now >= self.expires_at:
            return (
                "authorization expired before session start at "
                f"{self.expires_at.isoformat()}"
            )
        return None


_ROOT_KEYS = {"version", "authorization", "observation"}
_AUTHORIZATION_KEYS = {
    "id",
    "objective",
    "declared_actor",
    "scope",
    "operations",
    "constraints",
    "status",
}
_SCOPE_KEYS = {"allow", "deny"}
_OPERATIONS_KEYS = {"allow"}
_CONSTRAINT_KEYS = {"max_effects", "expires_at"}
_OBSERVATION_KEYS = {"exclude"}


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationError(f"{label} must be a mapping")
    return value


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise AuthorizationError(f"unknown {label} fields: {', '.join(unknown)}")


def _required_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"{label}.{key} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, label: str, *, required: bool = False) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or (required and not value):
        requirement = "a non-empty list" if required else "a list"
        raise AuthorizationError(f"{label} must be {requirement}")
    if any(not isinstance(item, str) for item in value):
        raise AuthorizationError(f"{label} must contain only strings")
    return tuple(item for item in value)


def _parse_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise AuthorizationError(f"{label} must be an ISO 8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AuthorizationError(f"{label} is not a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationError(f"{label} must include a UTC offset")
    return parsed


def load_authorization(path: Path) -> Authorization:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise AuthorizationError(f"cannot read authorization file: {path}") from exc
    try:
        document = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"invalid YAML in {path}: {exc}") from exc

    root = _mapping(document, "document")
    _reject_unknown(root, _ROOT_KEYS, "root")
    if root.get("version") != 1:
        raise AuthorizationError("version must be 1")

    raw_authorization = _mapping(root.get("authorization"), "authorization")
    _reject_unknown(raw_authorization, _AUTHORIZATION_KEYS, "authorization")
    raw_scope = _mapping(raw_authorization.get("scope"), "authorization.scope")
    _reject_unknown(raw_scope, _SCOPE_KEYS, "authorization.scope")
    raw_operations = _mapping(
        raw_authorization.get("operations"), "authorization.operations"
    )
    _reject_unknown(raw_operations, _OPERATIONS_KEYS, "authorization.operations")
    raw_constraints = _mapping(
        raw_authorization.get("constraints"), "authorization.constraints"
    )
    _reject_unknown(raw_constraints, _CONSTRAINT_KEYS, "authorization.constraints")

    raw_observation = _mapping(root.get("observation", {}), "observation")
    _reject_unknown(raw_observation, _OBSERVATION_KEYS, "observation")

    try:
        allow_paths = tuple(
            normalize_pattern(item)
            for item in _string_list(
                raw_scope.get("allow"), "authorization.scope.allow", required=True
            )
        )
        deny_paths = tuple(
            normalize_pattern(item)
            for item in _string_list(
                raw_scope.get("deny", []), "authorization.scope.deny"
            )
        )
        observation_exclude = tuple(
            normalize_pattern(item)
            for item in _string_list(
                raw_observation.get("exclude", []), "observation.exclude"
            )
        )
    except PatternError as exc:
        raise AuthorizationError(str(exc)) from exc

    raw_allowed_operations = _string_list(
        raw_operations.get("allow"),
        "authorization.operations.allow",
        required=True,
    )
    try:
        allowed_operations = frozenset(
            EffectKind(operation) for operation in raw_allowed_operations
        )
    except ValueError as exc:
        valid = ", ".join(item.value for item in EffectKind)
        raise AuthorizationError(
            f"authorization.operations.allow contains an invalid operation; "
            f"valid values: {valid}"
        ) from exc

    max_effects = raw_constraints.get("max_effects")
    if isinstance(max_effects, bool) or not isinstance(max_effects, int):
        raise AuthorizationError(
            "authorization.constraints.max_effects must be an integer"
        )
    if max_effects < 1:
        raise AuthorizationError(
            "authorization.constraints.max_effects must be at least 1"
        )

    raw_status = raw_authorization.get("status")
    try:
        status = AuthorizationStatus(raw_status)
    except ValueError as exc:
        valid = ", ".join(item.value for item in AuthorizationStatus)
        raise AuthorizationError(
            f"authorization.status must be one of: {valid}"
        ) from exc

    declared_actor = raw_authorization.get("declared_actor")
    if declared_actor is not None and (
        not isinstance(declared_actor, str) or not declared_actor.strip()
    ):
        raise AuthorizationError(
            "authorization.declared_actor must be a non-empty string when present"
        )

    return Authorization(
        authorization_id=_required_string(raw_authorization, "id", "authorization"),
        objective=_required_string(
            raw_authorization, "objective", "authorization"
        ),
        declared_actor=declared_actor.strip() if declared_actor else None,
        allow_paths=allow_paths,
        deny_paths=deny_paths,
        allowed_operations=allowed_operations,
        max_effects=max_effects,
        expires_at=_parse_datetime(
            raw_constraints.get("expires_at"),
            "authorization.constraints.expires_at",
        ),
        status=status,
        observation_exclude=observation_exclude,
        source_path=path.resolve(),
        source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def evaluate_effect(effect: Effect, authorization: Authorization) -> Effect:
    paths = [effect.path]
    if effect.previous_path is not None:
        paths.append(effect.previous_path)

    if effect.kind not in authorization.allowed_operations:
        effect.violations.append(f"OPERATION_NOT_ALLOWED:{effect.kind.value}")

    for path in paths:
        if matches_any(path, authorization.deny_paths):
            effect.violations.append(f"DENIED_PATH:{path}")
        elif not matches_any(path, authorization.allow_paths):
            effect.violations.append(f"OUTSIDE_ALLOWED_SCOPE:{path}")
    return effect

