from __future__ import annotations

import copy
import json
import os
import unittest
from pathlib import Path

from deep_tests.resident_operations import (
    ContractViolation,
    assert_no_active_overlap,
    declaration_names,
    load_json,
    sha256,
    validate_acceptance,
    validate_access_grant,
    validate_assignment_request,
    validate_guest_visit,
    validate_invoice,
    validate_payment,
    validate_persistence_receipt,
    validate_poll,
    validate_reservation,
    verify_targets,
)

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "contracts/resident-operations-targets.json").read_text(encoding="utf-8"))
HHM = Path(os.environ.get("HHM_INTERFACES_DIR", ".contract-cache/hhm-interfaces"))
CONTRACT = HHM / "contracts/resident-operations/v1"


def fixture(declaration: str, expectation: str, name: str) -> dict:
    return load_json(CONTRACT / "instances" / declaration / expectation / name)


class ResidentOperationsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not HHM.is_dir():
            raise unittest.SkipTest("the exact public HHM interface checkout is supplied by hosted CI")

    def assertViolation(self, callable_) -> None:
        with self.assertRaises(ContractViolation):
            callable_()

    def test_target_manifest_uses_immutable_commits(self) -> None:
        verify_targets(TARGETS)

    def test_expected_global_lock_links_the_exact_targets(self) -> None:
        expected = TARGETS["expectedGlobalContractLock"]
        self.assertEqual(expected["source"]["repository"], TARGETS["hackerHouseMedellinInterfaces"]["repository"])
        self.assertEqual(expected["source"]["commit"], TARGETS["hackerHouseMedellinInterfaces"]["commit"])
        self.assertEqual(expected["validator"], TARGETS["validator"])

    def test_expected_global_lock_digests_match_the_hhm_authorities(self) -> None:
        source = TARGETS["expectedGlobalContractLock"]["source"]
        self.assertEqual(sha256(CONTRACT / "main.tsp"), source["typespecSha256"])
        self.assertEqual(sha256(CONTRACT / "authored.schema.json"), source["jsonSchemaSha256"])

    def test_typespec_and_json_schema_declarations_match_exactly(self) -> None:
        tsp, schema = declaration_names(CONTRACT / "main.tsp", CONTRACT / "authored.schema.json")
        self.assertEqual(tsp, schema)
        self.assertEqual(len(tsp), 32)

    def test_required_corpus_has_valid_and_invalid_lanes(self) -> None:
        source = TARGETS["expectedGlobalContractLock"]["source"]
        root = CONTRACT / "instances"
        files = list(root.rglob("*.json"))
        self.assertGreaterEqual(len(files), source["minimumFiles"])
        for declaration in source["requiredDeclarations"]:
            self.assertTrue(list((root / declaration / "valid").glob("*.json")), declaration)
            self.assertTrue(list((root / declaration / "invalid").glob("*.json")), declaration)

    def test_guest_invitation_is_valid(self) -> None:
        validate_guest_visit(fixture("GuestVisit", "valid", "invited.json"))

    def test_guest_schedule_cannot_run_backward(self) -> None:
        value = fixture("GuestVisit", "valid", "invited.json")
        value["scheduledEnd"] = "2026-09-07T17:00:00Z"
        self.assertViolation(lambda: validate_guest_visit(value))

    def test_checked_out_guest_requires_ordered_checkpoints(self) -> None:
        value = fixture("GuestVisit", "valid", "invited.json")
        value["status"] = "checked_out"
        self.assertViolation(lambda: validate_guest_visit(value))
        value["checkedInAt"] = "2026-09-07T19:00:00Z"
        value["checkedOutAt"] = "2026-09-07T18:30:00Z"
        self.assertViolation(lambda: validate_guest_visit(value))

    def test_kitchen_reservation_is_valid(self) -> None:
        validate_reservation(fixture("ResourceReservation", "valid", "kitchen.json"))

    def test_active_reservations_cannot_overlap_the_same_resource(self) -> None:
        first = fixture("ResourceReservation", "valid", "kitchen.json")
        second = copy.deepcopy(first)
        second["reservationId"] = "66666666-6666-4666-8666-666666666666"
        second["startsAt"] = "2026-09-08T18:00:00Z"
        second["endsAt"] = "2026-09-08T20:00:00Z"
        self.assertViolation(lambda: assert_no_active_overlap([first, second]))
        second["startsAt"] = "2026-09-08T19:00:00Z"
        assert_no_active_overlap([first, second])

    def test_poll_fixture_is_valid(self) -> None:
        validate_poll(fixture("CommunityPoll", "valid", "meal-vote.json"))

    def test_poll_rejects_duplicate_options_and_excess_selections(self) -> None:
        value = fixture("CommunityPoll", "valid", "meal-vote.json")
        value["options"][1]["optionId"] = value["options"][0]["optionId"]
        self.assertViolation(lambda: validate_poll(value))
        value = fixture("CommunityPoll", "valid", "meal-vote.json")
        value["maxSelections"] = 3
        self.assertViolation(lambda: validate_poll(value))

    def test_closed_poll_requires_result_snapshot(self) -> None:
        value = fixture("CommunityPoll", "valid", "meal-vote.json")
        value["status"] = "closed"
        self.assertViolation(lambda: validate_poll(value))
        value["resultSnapshotId"] = "abababab-abab-4bab-8bab-abababababab"
        validate_poll(value)

    def test_paid_invoice_is_consistent(self) -> None:
        validate_invoice(fixture("RentInvoice", "valid", "september.json"))

    def test_invoice_rejects_overpayment_and_over_refund(self) -> None:
        value = fixture("RentInvoice", "valid", "september.json")
        value["amountPaidMinor"] = value["amountDueMinor"] + 1
        self.assertViolation(lambda: validate_invoice(value))
        value = fixture("RentInvoice", "valid", "september.json")
        value["amountRefundedMinor"] = value["amountPaidMinor"] + 1
        self.assertViolation(lambda: validate_invoice(value))

    def test_succeeded_payment_is_consistent(self) -> None:
        validate_payment(fixture("PaymentRecord", "valid", "stripe-success.json"))

    def test_payment_rejects_zero_amount_and_refund_above_settlement(self) -> None:
        self.assertViolation(lambda: validate_payment(fixture("PaymentRecord", "invalid", "zero-amount.json")))
        value = fixture("PaymentRecord", "valid", "stripe-success.json")
        value["refundedAmountMinor"] = value["amountMinor"] + 1
        self.assertViolation(lambda: validate_payment(value))

    def test_refunded_payment_requires_full_amount_and_refund_reference(self) -> None:
        value = fixture("PaymentRecord", "valid", "stripe-success.json")
        value["status"] = "refunded"
        self.assertViolation(lambda: validate_payment(value))
        value["refundedAmountMinor"] = value["amountMinor"]
        value["stripeRefundReference"] = "re_reference"
        validate_payment(value)

    def test_accepted_agreement_requires_digest_timestamp_and_server_receipt(self) -> None:
        validate_acceptance(fixture("AgreementAcceptance", "valid", "resident-terms.json"))
        self.assertViolation(lambda: validate_acceptance(fixture("AgreementAcceptance", "invalid", "bad-digest.json")))
        value = fixture("AgreementAcceptance", "valid", "resident-terms.json")
        del value["serverReceiptId"]
        self.assertViolation(lambda: validate_acceptance(value))

    def test_browser_and_supabase_receipts_cannot_claim_canonical_authority(self) -> None:
        value = fixture("PersistenceReceipt", "valid", "indexeddb-cache.json")
        validate_persistence_receipt(value)
        for store in ("local_storage", "indexed_db", "supabase"):
            candidate = dict(value, store=store, canonical=True)
            self.assertViolation(lambda candidate=candidate: validate_persistence_receipt(candidate))
        validate_persistence_receipt(dict(value, store="neon_postgres", canonical=True))

    def test_assignment_fixture_is_pseudonymous_and_valid(self) -> None:
        validate_assignment_request(fixture("AssignmentRequest", "valid", "room-plan.json"))

    def test_assignment_rejects_empty_duplicate_or_email_like_candidates(self) -> None:
        self.assertViolation(lambda: validate_assignment_request(fixture("AssignmentRequest", "invalid", "empty-candidates.json")))
        value = fixture("AssignmentRequest", "valid", "room-plan.json")
        value["candidateIds"] = ["candidate:01", "candidate:01"]
        self.assertViolation(lambda: validate_assignment_request(value))
        value["candidateIds"] = ["resident@example.com"]
        self.assertViolation(lambda: validate_assignment_request(value))

    def test_assignment_rejects_protected_payload_fields_recursively(self) -> None:
        value = fixture("AssignmentRequest", "valid", "room-plan.json")
        value["constraints"] = {"residentEmail": "resident@example.com"}
        self.assertViolation(lambda: validate_assignment_request(value))
        value["constraints"] = {"nested": [{"stripeCustomer": "cus_secret"}]}
        self.assertViolation(lambda: validate_assignment_request(value))

    def test_developer_grant_must_expire_and_be_unique(self) -> None:
        value = {
            "approvedAt": "2026-09-06T12:00:00Z",
            "expiresAt": "2026-09-07T12:00:00Z",
            "status": "active",
            "scopes": ["github:read", "logs:read"],
            "resourceReferences": ["repo:hhaus-api-server.rs"],
        }
        validate_access_grant(value)
        value["expiresAt"] = value["approvedAt"]
        self.assertViolation(lambda: validate_access_grant(value))
        value["expiresAt"] = "2026-09-07T12:00:00Z"
        value["scopes"] = ["github:read", "github:read"]
        self.assertViolation(lambda: validate_access_grant(value))


if __name__ == "__main__":
    unittest.main()
