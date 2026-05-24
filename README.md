# agent-trust-fabric (ATF)

> A neutral, federated, OSS substrate for AI agents to discover, delegate,
> verify, and audit collaboration across vendors and developers.

ATF is to inter-agent collaboration what TLS + Sigstore + OAuth are to HTTP:
the trust, attestation, scoped delegation, and tamper-evident audit layer
that the wire protocol itself leaves undefined.

## Status

**v0.1.0 (alpha)** — MVP layers (L0, L1 min, L4, L6 min, L7) implemented in
Python. Tests pass; demo runs. Pre-standardization.

## Why this exists

In 2026, AI agents increasingly act outside their own domain — calling
other agents (same vendor or different), accessing shared knowledge, taking
actions with real-world consequences. A2A (Agent-to-Agent) and MCP (Model
Context Protocol) provide the wire and tool-call substrates. But three
things are still missing in a vendor-neutral, federated form:

1. **Trust without a central authority** — agents from different developers
   meeting for the first time need to verify each other.
2. **Scoped delegation that's verifiable offline** — "I authorize you to do
   exactly X for Y minutes" with cryptographic proof.
3. **Audit that survives competing parties** — when Anthropic's agent and
   OpenAI's agent collaborate, neither's audit log can be the source of
   truth unilaterally.

ATF fills these gaps with **cross-signed audit events**, **JWS-Ed25519
delegation tokens**, and a **pluggable identity layer**.

## Quickstart

```bash
cd reference/py
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Run the test suite (30 tests, ~2 seconds)
.venv/bin/pytest

# Run the end-to-end demo (single-developer multi-agent)
.venv/bin/python -m examples.coding_to_image.run
```

The demo runs the full 11-step delegation flow:

```
 1. Bootstrap identities (Ed25519 keypairs, well-known URIs)
 2. Publish capability manifests
 3. Register peers (in production this is via well-known URIs)
 4. A issues a scoped delegation token (JWS, Ed25519, 60s TTL)
 5. A invokes B over HTTP with the token
 6. (B side) verified signature, exp, sub, scope, manifest
 7. (B side) executed image.generate handler
 8. (B side) signed outcome and built completion audit event
 9. (A side) verified outcome signature, schema, hash
10. (A side) co-signed the audit event, stored finalized
11. (A side) pushed A's signature back to B via /atf/v1/audit/cosign

✓ End-to-end delegation completed.
```

## CLI

```bash
.venv/bin/atf init example.com.coding              # bootstrap identity
.venv/bin/atf publish example.com.coding --cap code.write
.venv/bin/atf delegate example.com.coding \
    --to "agent://example.com/image#1" \
    --scope image.generate \
    --purpose "blog illustration"
.venv/bin/atf audit ls example.com.coding
.venv/bin/atf decode <token>                       # inspect a JWS without verifying
```

## Documents

- [Design (full spec)](./docs/specs/2026-05-23-atf-design.md) — architectural
  source of truth for the MVP
- [Vision](./docs/vision.md) — long-term roadmap (L0–L9 stack)
- ADRs in [`decisions/`](./decisions/)

## What ships in v0.1

| Layer | Status |
|---|---|
| L0 Identity (Ed25519, JWK Set, agent URI) | ✅ |
| L1 Capability Manifest (minimal, signed) | ✅ |
| L4 Scoped Delegation (JWS, alg=EdDSA fixed) | ✅ |
| L6 Outcome Verification (signed, schema, hash) | ✅ |
| L7 Federated Audit (cross-signed, SQLite) | ✅ |
| HTTP wire (FastAPI server + httpx client) | ✅ |
| CLI | ✅ |
| Python SDK | ✅ |
| TypeScript SDK | ⏭ post-MVP |
| L2 Discovery / L3 Attestation / L5 Context / L8 / L9 | ⏭ post-MVP |

## License

Apache 2.0 (planned).
