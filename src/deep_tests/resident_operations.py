"""Reference invariants for the H/HAUS resident-operations v1 contract."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CURRENCY = re.compile(r"^[A-Z]{3}$")
OPAQUE_ID = re.compile(r"^[A-Za-z0-9:._-]{1,255}$")
FORBIDDEN_SOLVER_KEYS = {
    "name",
    "email",
    "phone",
    "contact",
    "document",
    "payment",
    "stripe",
    "agreement",
    "legal",
    "chat",
    "health",
    "medical",
    "allergy",
    "dietary",
}


class ContractViolation(ValueError):
    """Raised when a record violates a lifecycle rule outside structural schema."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractViolation(message)


def _time(value: object, field: str) -> datetime:
    _require(isinstance(value, str) and value, f"{field} must be an RFC 3339 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractViolation(f"{field} must be an RFC 3339 timestamp") from exc


def _int(value: object, field: str, minimum: int = 0) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer")
    _require(value >= minimum, f"{field} must be >= {minimum}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def declaration_names(typespec: Path, authored_schema: Path) -> tuple[set[str], set[str]]:
    source = typespec.read_text(encoding="utf-8")
    tsp_names = set(re.findall(r'@id\("([A-Za-z0-9_]+)"\)\s*(?:enum|model|scalar|union)\s+([A-Za-z0-9_]+)', source))
    mismatched = sorted((identifier, declaration) for identifier, declaration in tsp_names if identifier != declaration)
    _require(not mismatched, f"TypeSpec @id/declaration mismatch: {mismatched}")
    schema = json.loads(authored_schema.read_text(encoding="utf-8"))
    _require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "wrong JSON Schema dialect")
    definitions = schema.get("$defs")
    _require(isinstance(definitions, dict), "authored schema must contain $defs")
    return {identifier for identifier, _ in tsp_names}, set(definitions)


def validate_guest_visit(record: Mapping[str, Any]) -> None:
    start = _time(record.get("scheduledStart"), "scheduledStart")
    end = _time(record.get("scheduledEnd"), "scheduledEnd")
    _require(end > start, "scheduledEnd must be after scheduledStart")
    status = record.get("status")
    checked_in = record.get("checkedInAt")
    checked_out = record.get("checkedOutAt")
    if status in {"checked_in", "checked_out"}:
        _require(checked_in is not None, f"{status} requires checkedInAt")
    if checked_in is not None:
        checked_in_at = _time(checked_in, "checkedInAt")
        _require(start <= checked_in_at <= end, "checkedInAt must be within the scheduled visit")
    else:
        checked_in_at = None
    if status == "checked_out":
        _require(checked_out is not None, "checked_out requires checkedOutAt")
    if checked_out is not None:
        checked_out_at = _time(checked_out, "checkedOutAt")
        _require(checked_in_at is not None, "checkedOutAt requires checkedInAt")
        _require(checked_out_at >= checked_in_at, "checkedOutAt must not precede checkedInAt")


def validate_reservation(record: Mapping[str, Any]) -> None:
    start = _time(record.get("startsAt"), "startsAt")
    end = _time(record.get("endsAt"), "endsAt")
    _require(end > start, "endsAt must be after startsAt")
    _int(record.get("partySize"), "partySize", 1)


def assert_no_active_overlap(records: Iterable[Mapping[str, Any]]) -> None:
    active = [record for record in records if record.get("status") in {"requested", "confirmed"}]
    grouped: dict[tuple[object, object, object], list[Mapping[str, Any]]] = {}
    for record in active:
        validate_reservation(record)
        key = (record.get("tenantId"), record.get("propertyId"), record.get("resourceId"))
        grouped.setdefault(key, []).append(record)
    for key, values in grouped.items():
        ordered = sorted(values, key=lambda value: _time(value.get("startsAt"), "startsAt"))
        for left, right in zip(ordered, ordered[1:]):
            _require(
                _time(left.get("endsAt"), "endsAt") <= _time(right.get("startsAt"), "startsAt"),
                f"active reservations overlap for {key}",
            )


def validate_poll(record: Mapping[str, Any]) -> None:
    opens = _time(record.get("opensAt"), "opensAt")
    closes = _time(record.get("closesAt"), "closesAt")
    _require(closes > opens, "closesAt must be after opensAt")
    options = record.get("options")
    _require(isinstance(options, list) and len(options) >= 2, "poll requires at least two options")
    ids = [option.get("optionId") for option in options if isinstance(option, Mapping)]
    labels = [option.get("label") for option in options if isinstance(option, Mapping)]
    _require(len(ids) == len(options), "every option must be an object")
    _require(len(ids) == len(set(ids)), "option IDs must be unique")
    _require(len(labels) == len(set(labels)), "option labels must be unique")
    max_selections = _int(record.get("maxSelections"), "maxSelections", 1)
    _require(max_selections <= len(options), "maxSelections cannot exceed option count")
    _int(record.get("quorum"), "quorum", 1)
    if record.get("status") == "closed":
        _require(record.get("resultSnapshotId") is not None, "closed poll requires immutable resultSnapshotId")


def validate_invoice(record: Mapping[str, Any]) -> None:
    due = _int(record.get("amountDueMinor"), "amountDueMinor")
    paid = _int(record.get("amountPaidMinor"), "amountPaidMinor")
    refunded = _int(record.get("amountRefundedMinor"), "amountRefundedMinor")
    _require(paid <= due, "amountPaidMinor cannot exceed amountDueMinor")
    _require(refunded <= paid, "amountRefundedMinor cannot exceed amountPaidMinor")
    currency = record.get("currency")
    _require(isinstance(currency, str) and CURRENCY.fullmatch(currency) is not None, "currency must be uppercase ISO-like code")
    status = record.get("status")
    if status == "paid":
        _require(paid == due and refunded == 0, "paid invoice must be fully settled and not refunded")
    if status == "refunded":
        _require(paid > 0 and refunded == paid, "refunded invoice must refund its paid amount")
    if status == "partially_refunded":
        _require(0 < refunded < paid, "partially_refunded invoice requires a partial refund")


def validate_payment(record: Mapping[str, Any]) -> None:
    amount = _int(record.get("amountMinor"), "amountMinor", 1)
    refunded = _int(record.get("refundedAmountMinor"), "refundedAmountMinor")
    _require(refunded <= amount, "refundedAmountMinor cannot exceed amountMinor")
    currency = record.get("currency")
    _require(isinstance(currency, str) and CURRENCY.fullmatch(currency) is not None, "currency must be uppercase ISO-like code")
    key = record.get("idempotencyKey")
    _require(isinstance(key, str) and 16 <= len(key) <= 128, "idempotencyKey length is invalid")
    status = record.get("status")
    if status in {"succeeded", "partially_refunded", "refunded", "disputed"}:
        _require(bool(record.get("stripePaymentReference")), f"{status} requires stripePaymentReference")
    if status == "refunded":
        _require(refunded == amount and bool(record.get("stripeRefundReference")), "refunded payment requires full refund reference")
    if status == "partially_refunded":
        _require(0 < refunded < amount and bool(record.get("stripeRefundReference")), "partial refund state is inconsistent")


def validate_acceptance(record: Mapping[str, Any]) -> None:
    digest = record.get("documentSha256")
    _require(isinstance(digest, str) and HEX_64.fullmatch(digest) is not None, "documentSha256 must be lowercase SHA-256")
    _time(record.get("startedAt"), "startedAt")
    if record.get("status") == "accepted":
        _require(record.get("acceptedAt") is not None, "accepted agreement requires acceptedAt")
        _time(record.get("acceptedAt"), "acceptedAt")
        _require(bool(record.get("serverReceiptId")), "accepted agreement requires a server receipt")


def validate_persistence_receipt(record: Mapping[str, Any]) -> None:
    store = record.get("store")
    canonical = record.get("canonical")
    _require(isinstance(canonical, bool), "canonical must be boolean")
    if canonical:
        _require(store == "neon_postgres", "only neon_postgres server receipts may be canonical")
    if store in {"local_storage", "indexed_db", "supabase"}:
        _require(canonical is False, f"{store} is a mirror/cache, not canonical authority")


def _walk_solver_payload(value: object, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            lowered = key.lower()
            _require(not any(word in lowered for word in FORBIDDEN_SOLVER_KEYS), f"forbidden solver field at {'.'.join(path + (key,))}")
            _walk_solver_payload(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_solver_payload(child, path + (str(index),))


def validate_assignment_request(record: Mapping[str, Any]) -> None:
    _walk_solver_payload(record)
    for field in ("candidateIds", "resourceIds"):
        values = record.get(field)
        _require(isinstance(values, list) and values, f"{field} must be non-empty")
        _require(len(values) == len(set(values)), f"{field} must not contain duplicates")
        for value in values:
            _require(isinstance(value, str) and OPAQUE_ID.fullmatch(value) is not None, f"{field} values must be opaque IDs")
            _require("@" not in value, f"{field} must not contain email-like values")


def validate_access_grant(record: Mapping[str, Any]) -> None:
    approved = _time(record.get("approvedAt"), "approvedAt")
    expires = _time(record.get("expiresAt"), "expiresAt")
    _require(expires > approved, "expiresAt must be after approvedAt")
    scopes = record.get("scopes")
    resources = record.get("resourceReferences")
    _require(isinstance(scopes, list) and scopes and len(scopes) == len(set(scopes)), "scopes must be non-empty and unique")
    _require(isinstance(resources, list) and resources and len(resources) == len(set(resources)), "resourceReferences must be non-empty and unique")
    if record.get("status") == "revoked":
        _require(record.get("revokedAt") is not None, "revoked grant requires revokedAt")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def verify_targets(targets: Mapping[str, Any]) -> None:
    _require(targets.get("schema") == "hhm-test.resident-operations-targets/v1", "wrong target schema")
    for name in ("hackerHouseMedellinInterfaces", "hhausInterfaces", "validator"):
        record = targets.get(name)
        _require(isinstance(record, Mapping), f"missing target {name}")
        commit = record.get("commit")
        _require(isinstance(commit, str) and HEX_40.fullmatch(commit) is not None, f"{name} must pin a full commit")
        repository = record.get("repository")
        _require(isinstance(repository, str) and repository.count("/") == 1, f"{name} repository must be owner/name")

    expected = targets.get("expectedGlobalContractLock")
    _require(isinstance(expected, Mapping), "missing expectedGlobalContractLock")
    source = expected.get("source")
    validator = expected.get("validator")
    _require(isinstance(source, Mapping), "expected global source must be an object")
    _require(isinstance(validator, Mapping), "expected global validator must be an object")
    _require(source.get("repository") == targets["hackerHouseMedellinInterfaces"]["repository"], "global source repository target drift")
    _require(source.get("commit") == targets["hackerHouseMedellinInterfaces"]["commit"], "global source commit target drift")
    _require(dict(validator) == dict(targets["validator"]), "global validator target drift")
    for name in ("typespecSha256", "jsonSchemaSha256"):
        value = source.get(name)
        _require(isinstance(value, str) and HEX_64.fullmatch(value) is not None, f"{name} must be lowercase SHA-256")
    minimum = source.get("minimumFiles")
    declarations = source.get("requiredDeclarations")
    _require(isinstance(minimum, int) and minimum >= 2, "minimumFiles must be at least two")
    _require(isinstance(declarations, list) and declarations, "requiredDeclarations must be non-empty")
    _require(all(isinstance(value, str) and value for value in declarations), "requiredDeclarations must contain names")
    _require(len(declarations) == len(set(declarations)), "requiredDeclarations must be unique")
