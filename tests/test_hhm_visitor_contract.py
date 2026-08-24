import hashlib
import json
import unittest
from pathlib import Path

from deep_tests.hhm_visitor_contract import (
    BoundedQrRedemptions,
    OneTimeCheckoutReceipts,
    RedemptionRejected,
    VisitorQrCodec,
    VisitorQrExpired,
    VisitorQrRejected,
)


FIXTURE = json.loads(
    Path("fixtures/hhm_visitor_cases.json").read_text(encoding="utf-8")
)


class HhmVisitorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        signing_material = hashlib.sha256(b"deterministic-public-test-material").digest()
        self.codec = VisitorQrCodec(
            signing_material,
            set(FIXTURE["allowed_doors"]),
            grace_seconds=FIXTURE["grace_seconds"],
        )
        self.now = FIXTURE["issued_at_epoch"]

    def test_fixture_tracks_the_current_public_contract(self) -> None:
        issued = self.codec.issue("front-door", "check_in", self.now)
        self.assertEqual(issued.claims.schema, FIXTURE["contract"])
        self.assertEqual(issued.claims.audience, FIXTURE["audience"])
        self.assertTrue(issued.payload.startswith(FIXTURE["presentation_prefix"]))
        self.assertEqual(issued.expires_at, (self.now // 60 + 1) * 60 + 15)

    def test_qr_is_stable_within_a_minute_and_rotates_at_the_boundary(self) -> None:
        first = self.codec.issue("front-door", "check_in", self.now)
        same_minute = self.codec.issue("front-door", "check_in", self.now + 20)
        next_minute = self.codec.issue("front-door", "check_in", self.now + 50)
        self.assertEqual(first.token, same_minute.token)
        self.assertNotEqual(first.token, next_minute.token)

    def test_qr_is_bound_to_door_and_action(self) -> None:
        issued = self.codec.issue("front-door", "check_in", self.now)
        for wrong_binding in FIXTURE["wrong_bindings"]:
            with self.subTest(wrong_binding=wrong_binding), self.assertRaises(
                VisitorQrRejected
            ):
                self.codec.verify(
                    issued.token,
                    expected_door=wrong_binding["expected_door"],
                    expected_action=wrong_binding["expected_action"],
                    now=self.now,
                )

    def test_minute_window_rejects_future_and_expired_codes(self) -> None:
        issued = self.codec.issue("front-door", "check_in", self.now)
        minute_start = self.now // 60 * 60
        self.codec.verify(
            issued.token,
            expected_door="front-door",
            expected_action="check_in",
            now=issued.expires_at,
        )
        with self.assertRaises(VisitorQrExpired):
            self.codec.verify(
                issued.token,
                expected_door="front-door",
                expected_action="check_in",
                now=minute_start - 1,
            )
        with self.assertRaises(VisitorQrExpired):
            self.codec.verify(
                issued.token,
                expected_door="front-door",
                expected_action="check_in",
                now=issued.expires_at + 1,
            )

    def test_tampering_and_presentation_prefix_are_rejected(self) -> None:
        issued = self.codec.issue("front-door", "check_in", self.now)
        tampered = f"{issued.token[:-1]}{'A' if issued.token[-1] != 'A' else 'B'}"
        for invalid in (tampered, issued.payload, f"{issued.token}.extra"):
            with self.subTest(invalid=invalid[:24]), self.assertRaises(VisitorQrRejected):
                self.codec.verify(
                    invalid,
                    expected_door="front-door",
                    expected_action="check_in",
                    now=self.now,
                )

    def test_shared_minute_code_has_a_hard_redemption_budget(self) -> None:
        issued = self.codec.issue("front-door", "check_in", self.now)
        ledger = BoundedQrRedemptions(FIXTURE["maximum_redemptions_per_code"])
        for expected_count in range(1, FIXTURE["maximum_redemptions_per_code"] + 1):
            self.assertEqual(ledger.consume(issued.token), expected_count)
        with self.assertRaises(RedemptionRejected):
            ledger.consume(issued.token)

    def test_checkout_receipt_is_private_one_time_state(self) -> None:
        tagging_material = hashlib.sha256(b"deterministic-receipt-test-material").digest()
        ledger = OneTimeCheckoutReceipts(tagging_material)
        ledger.register("synthetic-visit", "synthetic-checkout-receipt")
        with self.assertRaises(RedemptionRejected):
            ledger.consume("synthetic-visit", "wrong-receipt")
        ledger.consume("synthetic-visit", "synthetic-checkout-receipt")
        with self.assertRaises(RedemptionRejected):
            ledger.consume("synthetic-visit", "synthetic-checkout-receipt")


if __name__ == "__main__":
    unittest.main()
