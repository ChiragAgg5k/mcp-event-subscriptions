"""Experimental event subscription records and a restricted JWE profile."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jwcrypto import jwe, jwk

MAX_BYTES = 64 * 1024
PROFILE = "mcp-subscription-envelope-v1"
HEADER = {
    "alg": "dir",
    "enc": "A256GCM",
    "typ": "mcp-subscription+jwe",
    "cty": "application/json",
}
SCHEMA = json.loads(
    files(__package__).joinpath("subscription-v1.schema.json").read_text()
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
WEBHOOK = "webhook"
"""Delivery to a callback URL, signed with the record's secret."""
PUSH = "push"
"""Delivery on a stream the subscriber holds open; the record has no callback."""


class RecordError(ValueError):
    """Invalid subscription data. Messages do not include the record."""


class EnvelopeError(ValueError):
    """Invalid, unauthenticated, or incorrectly bound envelope."""


class ExpiredSubscription(EnvelopeError):
    """The recovered subscription lease has expired."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("non-finite JSON value")


def _loads(value: str | bytes) -> Any:
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant)


def _encode(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _json_value(value: Any) -> None:
    if value is None or type(value) in (str, bool, int, float):
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            _json_value(item)
        return
    raise ValueError("non-JSON value")


def _stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _webhook(delivery: dict[str, Any]) -> None:
    """Semantic checks of a webhook delivery that the schema cannot express."""
    url = urlsplit(delivery["url"])
    # DNS, SSRF policy, and endpoint verification remain adapter responsibilities.
    if (
        url.scheme != "https"
        or not url.hostname
        or "@" in url.netloc
        or "#" in delivery["url"]
        or any(c.isspace() or ord(c) < 32 for c in delivery["url"])
    ):
        raise ValueError("invalid callback URL")
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("invalid callback port")
    secret = delivery["secret"][6:]
    raw = base64.b64decode(secret, validate=True)
    if not 24 <= len(raw) <= 64 or base64.b64encode(raw).decode() != secret:
        raise ValueError("invalid secret")


def validate_subscription(record: Any) -> dict[str, Any]:
    """Validate structure and semantics; return an independent JSON copy."""
    try:
        _json_value(record)
        encoded = _encode(record)
        if len(encoded) > MAX_BYTES or not VALIDATOR.is_valid(record):
            raise ValueError("invalid structure or size")
        if record["delivery"]["mode"] == WEBHOOK:
            _webhook(record["delivery"])
        expiry, refresh = (
            record["lease"]["expiresAt"],
            record["lease"]["refreshBefore"],
        )
        if (expiry is None) != (refresh is None):
            raise ValueError("inconsistent lease")
        if expiry is not None and _stamp(refresh) > _stamp(expiry):
            raise ValueError("invalid lease order")
        return _loads(encoded)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        raise RecordError("invalid subscription record") from error


def _context(context: Any, resource: str) -> dict[str, str]:
    if (
        type(context) is not dict
        or set(context) != {"server", "tenant", "resource"}
        or any(type(v) is not str or not v for v in context.values())
        or context["resource"] != resource
    ):
        raise EnvelopeError("invalid envelope context")
    return dict(context)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    if re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise EnvelopeError("invalid base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise EnvelopeError("invalid base64url") from error
    if _b64(raw) != value:
        raise EnvelopeError("noncanonical base64url")
    return raw


def _key(keys: Mapping[str, bytes], kid: str) -> jwk.JWK:
    if type(kid) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", kid) is None:
        raise EnvelopeError("invalid key identifier")
    material = keys.get(kid)
    if type(material) is not bytes or len(material) != 32:
        raise EnvelopeError("unknown or invalid encryption key")
    return jwk.JWK(kty="oct", k=_b64(material))


def seal(
    record: Any,
    keys: Mapping[str, bytes],
    *,
    active_key: str,
    context: dict[str, str],
) -> str:
    """Encrypt a validated record with a random IV and trusted storage context."""
    record = validate_subscription(record)
    context = _context(context, record["id"])
    key = _key(keys, active_key)
    payload = _encode({"profile": PROFILE, "context": context, "subscription": record})
    token = jwe.JWE(
        payload,
        protected=_encode({**HEADER, "kid": active_key}).decode(),
        algs=["dir", "A256GCM"],
    )
    token.add_recipient(key)
    compact = token.serialize(compact=True)
    if len(compact.encode()) > MAX_BYTES:
        raise EnvelopeError("envelope exceeds size limit")
    return compact


def open_envelope(
    token: str,
    keys: Mapping[str, bytes],
    *,
    expected_context: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authenticate, validate, bind and check expiry before returning a record."""
    try:
        if type(token) is not str or len(token) > MAX_BYTES or not token.isascii():
            raise EnvelopeError("invalid envelope size or encoding")
        parts = token.split(".")
        if len(parts) != 5 or parts[1]:
            raise EnvelopeError("invalid compact JWE")
        header_bytes, _, iv, ciphertext, tag = map(_unb64, parts)
        header = _loads(header_bytes)
        if (
            type(header) is not dict
            or set(header) != set(HEADER) | {"kid"}
            or any(header[k] != v for k, v in HEADER.items())
            or len(iv) != 12
            or len(tag) != 16
            or not ciphertext
        ):
            raise EnvelopeError("unsupported envelope header or framing")
        key = _key(keys, header["kid"])
        decoded = jwe.JWE(algs=["dir", "A256GCM"])
        decoded.deserialize(token, key=key)
        payload = _loads(decoded.payload)
        if (
            type(payload) is not dict
            or set(payload) != {"profile", "context", "subscription"}
            or payload["profile"] != PROFILE
        ):
            raise EnvelopeError("unsupported envelope payload")
        record = validate_subscription(payload["subscription"])
        expected = _context(expected_context, record["id"])
        if _context(payload["context"], record["id"]) != expected:
            raise EnvelopeError("envelope context mismatch")
        current = now if now is not None else datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise EnvelopeError("clock must be timezone-aware")
        expiry = record["lease"]["expiresAt"]
        if expiry is not None and current >= _stamp(expiry):
            raise ExpiredSubscription("subscription expired")
        return record
    except EnvelopeError:
        raise
    except Exception as error:
        # No raw token, secret, or decrypted record in the public error message.
        raise EnvelopeError("invalid encrypted subscription") from error


__all__ = [
    "PUSH",
    "WEBHOOK",
    "EnvelopeError",
    "ExpiredSubscription",
    "RecordError",
    "open_envelope",
    "seal",
    "validate_subscription",
]
