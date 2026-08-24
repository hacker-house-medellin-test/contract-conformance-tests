from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Final


QR_SCHEMA: Final = "hhm.visitor-qr.v1"
QR_AUDIENCE: Final = "hhm-api"
QR_PREFIX: Final = "hhm1"
PRESENTATION_PREFIX: Final = "hhm-visitor:"
SIGNATURE_CONTEXT: Final = b"hhm.visitor-qr.signature.v1\0"


class VisitorQrRejected(ValueError):
    pass


class VisitorQrExpired(VisitorQrRejected):
    pass


class RedemptionRejected(ValueError):
    pass


@dataclass(frozen=True)
class VisitorQrClaims:
    schema: str
    audience: str
    door_id: str
    action: str
    issued_minute: int


@dataclass(frozen=True)
class IssuedVisitorQr:
    claims: VisitorQrClaims
    token: str
    payload: str
    expires_at: int


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str) -> bytes:
    if not value or "=" in value:
        raise VisitorQrRejected("base64url values must be non-empty and unpadded")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise VisitorQrRejected("invalid base64url value") from error


class VisitorQrCodec:
    """Credential-free reference implementation of the HHM QR wire contract."""

    def __init__(
        self,
        signing_material: bytes,
        allowed_doors: set[str],
        *,
        grace_seconds: int = 15,
        max_token_bytes: int = 1_024,
        max_payload_bytes: int = 512,
    ) -> None:
        if len(signing_material) < 32:
            raise ValueError("test signing material must be at least 32 bytes")
        if not allowed_doors:
            raise ValueError("at least one door must be allowlisted")
        if grace_seconds < 0 or grace_seconds > 30:
            raise ValueError("QR grace must be narrowly bounded")
        self._signing_material = signing_material
        self._allowed_doors = frozenset(allowed_doors)
        self.grace_seconds = grace_seconds
        self.max_token_bytes = max_token_bytes
        self.max_payload_bytes = max_payload_bytes

    def issue(self, door_id: str, action: str, now: int) -> IssuedVisitorQr:
        self._validate_door(door_id)
        self._validate_action(action)
        issued_minute = now // 60
        claims = VisitorQrClaims(
            schema=QR_SCHEMA,
            audience=QR_AUDIENCE,
            door_id=door_id,
            action=action,
            issued_minute=issued_minute,
        )
        payload_bytes = json.dumps(
            claims.__dict__, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        encoded_payload = _encode_base64url(payload_bytes)
        signature = hmac.new(
            self._signing_material,
            SIGNATURE_CONTEXT + encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        token = f"{QR_PREFIX}.{encoded_payload}.{_encode_base64url(signature)}"
        return IssuedVisitorQr(
            claims=claims,
            token=token,
            payload=f"{PRESENTATION_PREFIX}{token}",
            expires_at=(issued_minute + 1) * 60 + self.grace_seconds,
        )

    def verify(
        self,
        token: str,
        *,
        expected_door: str,
        expected_action: str,
        now: int,
    ) -> VisitorQrClaims:
        if len(token.encode("utf-8")) > self.max_token_bytes:
            raise VisitorQrRejected("token exceeds the contract limit")
        self._validate_door(expected_door)
        self._validate_action(expected_action)
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != QR_PREFIX:
            raise VisitorQrRejected("invalid token envelope")
        encoded_payload, encoded_signature = parts[1], parts[2]
        if len(encoded_payload) > self.max_payload_bytes * 2:
            raise VisitorQrRejected("encoded payload exceeds the contract limit")

        signature = _decode_base64url(encoded_signature)
        expected_signature = hmac.new(
            self._signing_material,
            SIGNATURE_CONTEXT + encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise VisitorQrRejected("signature mismatch")

        payload = _decode_base64url(encoded_payload)
        if len(payload) > self.max_payload_bytes:
            raise VisitorQrRejected("decoded payload exceeds the contract limit")
        try:
            raw_claims = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VisitorQrRejected("invalid claims") from error
        expected_keys = {"schema", "audience", "door_id", "action", "issued_minute"}
        if not isinstance(raw_claims, dict) or set(raw_claims) != expected_keys:
            raise VisitorQrRejected("claims must use the exact schema")
        if isinstance(raw_claims["issued_minute"], bool) or not isinstance(
            raw_claims["issued_minute"], int
        ):
            raise VisitorQrRejected("issued_minute must be an integer")
        claims = VisitorQrClaims(**raw_claims)
        if (
            claims.schema != QR_SCHEMA
            or claims.audience != QR_AUDIENCE
            or claims.door_id != expected_door
            or claims.action != expected_action
            or claims.door_id not in self._allowed_doors
        ):
            raise VisitorQrRejected("claims are not bound to this request")

        issued_at = claims.issued_minute * 60
        expires_at = issued_at + 60 + self.grace_seconds
        if now < issued_at or now > expires_at:
            raise VisitorQrExpired("QR is outside its minute window")
        return claims

    def _validate_door(self, door_id: str) -> None:
        if door_id not in self._allowed_doors:
            raise VisitorQrRejected("door is not allowlisted")

    @staticmethod
    def _validate_action(action: str) -> None:
        if action not in {"check_in", "check_out"}:
            raise VisitorQrRejected("action is not part of the visitor contract")


class BoundedQrRedemptions:
    """Models the current shared QR budget without pretending it is one-use."""

    def __init__(self, maximum_per_token: int = 128) -> None:
        if maximum_per_token <= 0:
            raise ValueError("redemption maximum must be positive")
        self._maximum_per_token = maximum_per_token
        self._counts: dict[str, int] = {}

    def consume(self, token: str) -> int:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise RedemptionRejected("invalid QR token")
        key = hashlib.sha256(parts[2].encode("ascii")).hexdigest()
        count = self._counts.get(key, 0)
        if count >= self._maximum_per_token:
            raise RedemptionRejected("QR redemption budget exhausted")
        count += 1
        self._counts[key] = count
        return count


class OneTimeCheckoutReceipts:
    """Stores only receipt tags and rejects checkout replay."""

    def __init__(self, tagging_material: bytes) -> None:
        if len(tagging_material) < 32:
            raise ValueError("test tagging material must be at least 32 bytes")
        self._tagging_material = tagging_material
        self._receipt_tags: dict[str, bytes] = {}
        self._consumed_visits: set[str] = set()

    def register(self, visit_id: str, receipt: str) -> None:
        if not visit_id or not receipt:
            raise ValueError("visit and receipt are required")
        self._receipt_tags[visit_id] = self._tag(receipt)

    def consume(self, visit_id: str, receipt: str) -> None:
        if visit_id in self._consumed_visits:
            raise RedemptionRejected("visit was already checked out")
        expected = self._receipt_tags.get(visit_id)
        supplied = self._tag(receipt)
        if expected is None or not hmac.compare_digest(expected, supplied):
            raise RedemptionRejected("checkout receipt is invalid")
        self._consumed_visits.add(visit_id)
        del self._receipt_tags[visit_id]

    def _tag(self, receipt: str) -> bytes:
        return hmac.new(
            self._tagging_material,
            b"hhm.visitor-checkout-receipt.v1\0" + receipt.encode("utf-8"),
            hashlib.sha256,
        ).digest()
