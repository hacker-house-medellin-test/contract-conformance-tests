# hacker-house-medellin-test/contract-conformance-tests

Deterministic state-model, idempotency, serialization, and protocol contract conformance tests.

This repository is the `contract` deep-test suite for `hacker-house-medellin`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Resident operations v1

The resident-operations suite checks the exact public `hacker-house-medellin/hhm-interfaces` head and records the corresponding private `hhaus-org/hhaus-interfaces` review head in `contracts/resident-operations-targets.json`. Hosted CI does not receive a broad cross-org token: the private global repository verifies its own lock, while this public sibling suite independently verifies the expected lock metadata, source digests, 32 declaration identities, and positive/negative corpus lanes against the public HHM authority.

The reference-model tests enforce lifecycle rules that structural schemas cannot fully express: ordered guest check-in/out, non-overlapping active reservations, poll option and immutable-result rules, rent and refund bounds, canonical storage authority, legal server receipts, pseudonymous solver requests, recursive protected-data rejection, and time-bounded developer grants.

## Run

```bash
PYTHONPATH=src \
HHM_INTERFACES_DIR=/path/to/hhm-interfaces \
python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

Without the exact HHM interface checkout, the resident-operations class skips rather than fabricating evidence; the pre-existing local reference-model tests still run. Hosted CI supplies the immutable public revision from `contracts/resident-operations-targets.json`. The private global interface PR runs its own exact-checkout lock and parity job.

Tracking: `DEN-1950` and https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
