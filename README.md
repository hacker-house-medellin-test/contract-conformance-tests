# hacker-house-medellin-test/contract-conformance-tests

Deterministic state-model, idempotency, serialization, and protocol contract conformance tests.

This repository is the `contract` deep-test suite for `hacker-house-medellin`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

## HHM visitor-access coverage

The credential-free `hhm_visitor_contract` reference model exercises the current
backend-issued QR envelope and fixture contract:

- deterministic rotation on UTC minute boundaries with the 15-second grace;
- exact schema, audience, allowlisted door, and sign-in/sign-out action binding;
- HMAC tamper detection plus future and expiry rejection;
- the current bounded shared-code redemption budget, without misrepresenting a
  minute QR as a one-use credential; and
- one-time private checkout receipt consumption and replay rejection.

The fixture contains synthetic metadata only. It does not contain a production
QR, receipt, signing key, visitor identity, or authentication credential.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
