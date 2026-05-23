# ATF Design Specification

- **Project**: agent-trust-fabric (ATF)
- **Document type**: Design specification (architectural source of truth)
- **Date**: 2026-05-23
- **Status**: Draft (pre-implementation)
- **Authors**: Shinichi Kimura + Claude (collaborative brainstorming)
- **Decision criteria**: See [ADR-0001](../../decisions/0001-design-criteria.md)

---

## 0. Reading order

This document is the source of truth for the MVP architecture. Sections 1–5
correspond to the brainstorming flow that produced it; Section 6 fixes the
MVP scope; Section 7 outlines the post-MVP roadmap.

For an implementation plan, see `docs/specs/2026-05-23-atf-plan.md`
(produced by the writing-plans skill after this document is approved).

---

## 1. Overview

### 1.1 One-line definition

ATF is a **neutral, federated, open-source substrate** that lets AI agents
from different vendors and developers — who do not know each other a priori —
**discover, delegate to, verify, and audit each other** across organizational
and trust boundaries.

### 1.2 What this is NOT

- ❌ Not a wire-protocol competitor to A2A or MCP. A2A handles agent↔agent
  transport; MCP handles agent↔tool. ATF is the **trust / delegation / audit**
  layer that both leave undefined.
- ❌ Not a SaaS. There is no central server in the core protocol. A reference
  implementation is shipped, but anyone can run their own.
- ❌ Not an LLM observability platform (Langfuse / Braintrust / etc.). ATF
  does not capture token usage, prompts, or model traces for evaluation
  purposes.
- ❌ Not a multi-agent orchestration framework (CrewAI, LangGraph). ATF is
  pluggable underneath whatever orchestrator the user picks.

### 1.3 Why now (2026-05)

Three signals from market research:

1. **A2A v1.0 (2026 early) explicitly leaves agent-card authenticity, trust
   establishment between first-meeting agents, and cross-developer delegation
   chains as "implementer's choice"** — i.e., unsolved at the protocol level.
   (Source: VentureBeat RSAC 2026; arXiv 2505.12490.)
2. **45.6% of teams still use shared API keys for agent authentication**, and
   only 7–8% of organizations have mature cross-agent governance.
3. **NIST CAISI launched the AI Agent Standards Initiative in 2026-02** — a
   federal-level push for interoperable identity, but still in early stages.

The substrate is missing. ATF aims to fill it.

### 1.4 Design principles (5)

1. **Vendor-neutral by design** — Apache 2.0, no single-company control.
2. **Federated, no central server** — each agent owns its own identity and
   audit log. Central registries are strictly optional.
3. **Verification-first** — borrowed from Addy Osmani's observation that
   "the bottleneck is verification, not generation." Signing, attestation,
   and audit are not opt-out for core operations.
4. **Standards-over-invention** — ~80% of ATF is composition of existing
   standards (JWS, OAuth-style scopes, Sigstore-style transparency, OTel
   for self-observability). ~20% is genuinely new (cross-signed audit,
   outcome verification primitives).
5. **Layered, not monolithic** — see the L0–L9 stack in §2.1. Layers ship
   independently; MVP is L0 + L1(min) + L4 + L6(min) + L7.

### 1.5 Use cases

1. **Single-developer multi-agent** (MVP demo target) — one developer ships
   several agents in their own product (e.g., a Coding Agent that delegates
   to an Image Agent). ATF gives them clean delegation, scoped permissions,
   and an audit trail without inventing it themselves.
2. **Same-organization cross-team** — a company's Coding Agent (Eng team)
   delegates to its Infra Agent (Ops team); each team owns its agent but
   they collaborate through ATF for policy enforcement and audit.
3. **Cross-vendor strategic collaboration** (v2 ambition) — Anthropic's
   agent delegates a sub-task to OpenAI's agent (or vice versa). Neither
   trusts the other's audit unilaterally, so ATF cross-signed events make
   the collaboration provable.

---

## 2. Architecture

### 2.1 The L0–L9 stack

| Layer | Name | Purpose | Borrowed from | MVP? |
|---|---|---|---|---|
| L0 | Identity | "I am this agent" with verifiable keys | SPIFFE / DID / Okta-for-AI | ✅ |
| L1 | Capability Manifest | "I can do these things" (signed) | A2A Agent Card | ✅ (minimal) |
| L2 | Discovery | "Who can do X?" | DNS, A2A discovery | ⏭ v2 |
| L3 | Trust / Attestation | "This agent is endorsed by …" | Sigstore | ⏭ v2 |
| L4 | Scoped Delegation | "I authorize you to do X for Yh" | OAuth2 + JWS | ✅ |
| L5 | Context Sharing | Provenance-tagged knowledge handoff | (new) | ⏭ v2 |
| L6 | Outcome Verification | "Did B actually do what was asked?" | (new, minimal) | ✅ (minimal) |
| L7 | Federated Audit | Tamper-evident cross-party log | Sigstore Rekor + CT gossip | ✅ |
| L8 | Settlement | Cost / credit accounting | Stripe Connect (adapter) | ❌ out of scope |
| L9 | Escalation | Mediation, HITL | (domain-specific) | ❌ out of scope |

### 2.2 SDK public surface (Python, MVP)

```python
from atf import Agent

# L0: identity bootstrap (Ed25519 keypair, self-signed)
me = Agent.create(
    name="claude-coding-agent",
    owner="findy.co.jp",
)

# L1: publish capability manifest (A2A Agent Card schema + ATF signature)
me.publish_manifest(capabilities=[
    "code.read", "code.write", "code.review.python",
])

# L4: issue scoped delegation token (JWS, alg=Ed25519 fixed)
token = me.delegate(
    to="agent://findy.co.jp/image-gen#1",
    scope=["image.generate"],
    constraints={"max_cost_usd": 0.50, "purpose": "blog illustration"},
    expires_in="1h",
)

# L4 verify + L6 outcome handling on B's side
verifier = Agent.from_uri("agent://findy.co.jp/claude#1")
if verifier.verify(token):
    result = do_image_gen(...)
    me.audit.record_outcome(token, result)   # L7 cross-signed event
```

### 2.3 Layer details (MVP)

#### L0 — Identity

- **Form**: `agent://<owner-domain>/<name>#<kid>` URI + a JWK Set at a
  well-known URI (`https://<owner-domain>/.well-known/atf/jwks.json`).
- **Algorithm**: Ed25519 only in MVP (alg confusion mitigation).
- **Identity document**: `{ id, jwks_uri, owner_org, attestations[], manifest_uri }`.
- **Bootstrap**: self-signed at creation. Third-party attestations can be
  added later, building a trust graph.
- **Pluggable bindings**: DID, X.509, SPIFFE SVID are accepted as optional
  identity proofs in the `attestations[]` field, but not required.

#### L1 — Capability Manifest (minimal)

- **Schema**: A2A Agent Card schema, adopted unchanged.
- **Wrapper**: ATF adds a detached JWS signature over the canonical
  serialization, plus an `evidence[]` array for capability proofs from
  third parties.
- **Capability format**: `verb.scope[.qualifier]`, hierarchical
  (e.g., `code.write.python`, `deploy.staging`).
- **Publication**: the manifest is hosted by the agent's owner at a stable
  URI; consumers fetch and verify the JWS.

#### L4 — Scoped Delegation Token

- **Form**: JWS (not JWT) with a fixed ATF claim envelope. `alg` constrained
  to Ed25519 (anti–algorithm-confusion).
- **Required claims**: `iss, sub, scope, exp, nbf, jti, purpose, constraints,
  audit_uri, payload_hash`.
- **Lifetime**: 1h default, 24h max.
- **Verification**: offline, using the issuer's JWK fetched from L0.
- **Revocation**: short TTL by design; emergency revocation as a
  `key.revoked` event broadcast to known peers and recorded in audit.
- **Future**: Macaroons evaluated for v2 because their caveat-attenuation
  model maps better onto multi-hop delegation.

#### L6 — Outcome Verification (minimal)

- Every outcome returned by the delegatee is **signed** by the delegatee's
  key.
- Outcomes carry `{ status, payload, payload_hash, schema_id, signed_at,
  signature }`.
- The consumer validates the signature and validates `payload` against
  `schema_id`.
- `payload_hash` is recorded in the audit event; the payload itself need
  not be (privacy).
- Deeper semantic verification (does the generated code work, does the
  image match intent, etc.) is **out of scope** — it lives at the domain
  layer or in L9 escalation.

#### L7 — Federated Audit Log (cross-signed)

- **Model**: every cross-agent event (`delegation.issued`,
  `delegation.completed`, `delegation.failed`, `delegation.disputed`,
  `key.revoked`) is recorded as an entry signed by **both** parties when
  the event involves both.
- **Cross-sign property**: an entry's `delegator.signature` and
  `delegatee.signature` are both required for `delegation.completed`.
  Neither party can rewrite history alone without the other detecting.
- **Local storage**: SQLite (or DuckDB) on each side, hash-chained.
- **Federation**: optional periodic publication of Merkle roots to public
  witnesses (Sigstore-style); not required for MVP.
- **Disputed events**: signed by only one party, used when the parties
  disagree about an outcome; ensures dissent is itself recorded.

### 2.4 Adapters (reference implementation ships these)

| Adapter | Role |
|---|---|
| ATF ↔ A2A | Maps A2A Agent Cards to ATF Manifests and embeds ATF tokens in A2A messages |
| ATF ↔ MCP | Wraps MCP tool calls with ATF delegation context |
| ATF ↔ OAuth2 | Maps OAuth2 scopes to ATF scopes for human-→-agent delegation |

### 2.5 Storage

- **Identity keys**: local key file; OS keychain integration optional.
- **Manifest**: HTTP-served static file on the owner's domain.
- **Audit log**: local SQLite/DuckDB. Exportable. No external dependency
  required for MVP.

---

## 3. Wire protocol and data flow

### 3.1 Actors

```
[Agent A: delegator]  ──ATF wire (HTTP+JSON, signed)──  [Agent B: delegatee]
                                                                │
                                                  (optional) [Witness W]
```

In MVP, A and B are typically two agents shipped by the same developer.
Witnesses are v2.

### 3.2 Happy path: 11 steps

```
[Setup — once per agent]
 1. Bootstrap       Generate keypair, derive agent_id, publish JWKS
 2. Manifest        Sign and publish capability manifest

[Per delegation]
 3. Resolve         A fetches B's JWKS + Manifest, verifies signatures
 4. Issue           A creates and signs a Delegation Token (JWS)
 5. Request         A → B:  POST /atf/v1/invoke  with token + payload
 6. Verify          B verifies: signature, exp, sub, scope, policy
 7. Execute         B performs the requested action
 8. Sign outcome    B signs the outcome (status, payload, hash, schema_id)
 9. Cross-Audit     A and B co-sign a single audit entry recording the result
10. Return          B → A:  signed outcome
11. Verify out      A verifies outcome signature + schema; on mismatch,
                    A records a delegation.disputed event
```

### 3.3 Wire format (HTTP + JSON)

```http
POST /atf/v1/invoke HTTP/1.1
Host: image-gen.findy.co.jp
Content-Type: application/atf+json; version=0.1
X-ATF-Token: eyJhbGciOiJFZERTQSIsImtpZCI6...

{
  "atf_version": "0.1",
  "request_id": "req_01HXY3...",
  "payload": {
    "action": "image.generate",
    "params": {"prompt": "...", "size": "1024x1024"}
  },
  "audit_uri": "https://findy.co.jp/atf/audit/claude/"
}
```

Response:

```json
{
  "atf_version": "0.1",
  "request_id": "req_01HXY3...",
  "outcome": {
    "status": "ok",
    "payload": {"image_url": "..."},
    "payload_hash": "sha256:...",
    "schema_id": "image.generate.v1",
    "executed_at": "2026-05-23T..."
  },
  "outcome_signature": "ed25519:...",
  "audit_event_ref": "evt_01HXY4..."
}
```

### 3.4 Cross-signed audit event

```json
{
  "event_id": "evt_01HXY4...",
  "ts": "2026-05-23T12:34:56Z",
  "type": "delegation.completed",
  "delegator": {
    "agent_id": "agent://findy.co.jp/claude#1",
    "signature": "ed25519:A_SIG..."
  },
  "delegatee": {
    "agent_id": "agent://findy.co.jp/image-gen#1",
    "signature": "ed25519:B_SIG..."
  },
  "token_jti": "tkn_01HXY3...",
  "outcome_hash": "sha256:...",
  "prev_hash_A": "sha256:...",
  "prev_hash_B": "sha256:...",
  "purpose": "blog illustration"
}
```

### 3.5 Threat model

| Attack | Mitigation |
|---|---|
| Impersonation | L0 key verification + L1 manifest signature |
| Privilege escalation | L4 token scope must be verified by delegatee |
| Hidden delegation | L7 cross-signed events (one side cannot delete) |
| Outcome tampering | L6 outcome signature + L7 hash recorded |
| Replay | `exp` + `jti` (duplicate detection) |
| Algorithm confusion | `alg=Ed25519` enforced via allow-list |
| MitM | TLS transport + end-to-end ATF signing |

Out of scope:
- Semantic correctness of AI output (hallucination) — domain layer
- Financial loss / overspend — defer to L8 adapter (Stripe etc.)
- Prompt injection — agent harness / MCP layer responsibility

### 3.6 Versioning and compatibility

- `atf_version` (semver) required in wire format and each layer schema.
- Compatibility guarantee: **2 minor versions backward** (v1.0 ↔ v1.2).
- Graceful degrade with non-ATF agents: absent `X-ATF-Token` → treat as
  normal HTTP; the requester records `outcome.missing_signature` if it
  needed an ATF outcome.

### 3.7 Privacy by default

- Audit log records hashes, not payloads.
- Token `constraints` should not contain PII (linted by SDK).
- Witness publication is opt-in.
- Audit export supports redaction policies.

---

## 4. Error handling

### 4.1 Failure classes

| Class | Examples | Policy |
|---|---|---|
| Pre-invoke | Bad key, expired token, scope mismatch | Reject; no audit (no harm) |
| Mid-invoke | Execution error, constraint violation | Partial audit, `status=failed` cross-signed |
| Post-invoke conflict | A and B disagree on outcome | `delegation.disputed` recorded by dissenter |
| Critical | Key compromise, signing failure | Emergency revocation, halt new invokes |

### 4.2 Per-step error semantics

Mapped against the 11-step happy path (§3.2):

| Step | Failure | HTTP / signal | Audit policy |
|---|---|---|---|
| 3 Resolve | JWKS unreachable | client abort | none (no harm yet) |
| 3 Resolve | Manifest signature invalid | abort + `manifest.invalid_signature` | A records attempt (possible attack) |
| 4 Issue | Scope outside A's own manifest | client-side reject | none |
| 6 Verify | Token expired | 401 `token.expired` | none |
| 6 Verify | Scope insufficient | 403 `token.insufficient_scope` | none |
| 6 Verify | `jti` replay | 409 `token.replay` | B records (attack signal) |
| 6 Verify | Signature bad | 401 `token.invalid_signature` | B records (attack signal) |
| 7 Execute | Internal error | outcome `status=error`, signed | cross-signed |
| 7 Execute | Constraint violation (cost cap) | outcome `status=refused`, signed | cross-signed |
| 8 Sign outcome | B cannot sign (key issue) | **critical** | emergency revoke event, notify A |
| 9 Cross-Audit | Local log write fails | retry 3× | see §4.4 below |
| 11 Verify out | Schema mismatch | A logs disputed | A-only `delegation.disputed` |

### 4.3 Disputed events

When parties disagree, a one-side-signed event is appended to the
dissenter's local log:

```json
{
  "type": "delegation.disputed",
  "ref_event_id": "evt_01HXY4...",
  "disputed_by": "agent://findy.co.jp/claude#1",
  "reason": "outcome.schema_mismatch",
  "evidence_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

This guarantees that **the existence of disagreement is itself logged** —
no party can pretend consensus existed.

### 4.4 Audit-write failure compensation

If cross-signing fails after B has executed:

1. B writes `delegation.started` to its local log **before** executing
   (pre-execution journal).
2. After execution, B retries cross-sign with exponential backoff (max 3).
3. On persistent failure, B writes `delegation.orphan_completed` locally
   and notifies A out-of-band.
4. A handles the late cross-sign event idempotently (dedup by `jti`).

### 4.5 Key compromise & rotation

| Situation | Response |
|---|---|
| A detects own key leak | New keypair → `key.revoked` event → manifest update → notify outstanding-token holders |
| B distrusts A's key | B refuses subsequent invokes; logs `trust.revoked` |
| Planned rotation | Overlap window; old key chained in `previous_keys[]` |

### 4.6 ATF-unaware peer

- ATF is opt-in. Non-ATF peers respond as plain HTTP.
- Requester records `outcome.missing_signature` if it required ATF.

### 4.7 Self-observability

ATF SDKs emit OTel metrics under the `atf.*` namespace: delegation count,
verify-failure rate, cross-sign failure rate, dispute ratio.

---

## 5. Testing strategy

### 5.1 Test pyramid (protocol-product shape)

```
   E2E scenarios       ← real delegation loops
   Conformance suite   ← external-implementation validation
   Integration tests   ← SDK × wire × audit
   Property tests      ← crypto / audit invariants
   Unit tests          ← primitives
```

### 5.2 Layers

- **Unit**: keypair gen, JWS encode/verify, manifest schema validation,
  audit hash-chain integrity.
- **Property-based (Hypothesis / fast-check)**: any-token-verifies-with-issuer-key;
  tampered-token-never-verifies; cross-signed-entry-requires-both-sigs;
  expired-token-never-accepted.
- **Integration**: A-SDK → wire → B-SDK round trips; parallel `jti`
  uniqueness; key rotation behavior.
- **Conformance suite**: external implementations can plug an adapter
  into a CLI runner and assert spec-compliance. JSON test vectors + HTTP
  fixtures. Lives at `tests/conformance/`.
- **E2E scenarios**: single-developer multi-agent (MVP target); disputed
  flow; key rotation under load; ATF-unaware peer mixing.
- **Security**: fuzz of token and wire parsers; `alg:none` and `alg:HS256`
  rejection; replay protection; constant-time signature compare.
- **Performance**: token verify < 1ms; audit append < 5ms; e2e invoke
  < 50ms (local network). Baselines tracked as regression tests.

### 5.3 CI

- Unit + conformance per PR.
- Security and perf weekly.
- All checks must pass before merging to `main`.

---

## 6. MVP scope (locked)

| Item | Decision |
|---|---|
| Layers in MVP | L0, L1 (minimal), L4, L6 (minimal), L7 |
| Layers in v2 | L2, L3, L5; L6 deeper |
| Out of scope | L8 (settlement), L9 (escalation) — adapters only |
| Reference languages | Python (priority), TypeScript (post-MVP) |
| Wire format | HTTP + JSON, signed via detached JWS |
| Identity | `agent://owner/name#kid` URI + JWK Set at well-known URI |
| Manifest schema | A2A Agent Card + ATF signature envelope |
| Token | JWS, alg=Ed25519 fixed, 1h default lifetime |
| Audit | Cross-signed events in local SQLite; federation optional |
| Demo target | Single-developer multi-agent (Coding Agent → Image Agent) |
| License | Apache 2.0 |

---

## 7. Roadmap (post-MVP)

| Phase | Goal |
|---|---|
| v0.1 | MVP shipped; passing conformance; single-developer demo |
| v0.2 | L2 Discovery + L3 Attestation; same-org cross-team demo |
| v0.3 | L5 Context Sharing; richer L6 verification primitives |
| v0.4 | A2A and MCP adapters production-grade |
| v0.5 | TypeScript SDK to parity |
| v1.0 | Cross-vendor demo (Claude ↔ different vendor); witness federation |

---

## 8. Open questions

These are not blocking MVP but need answers before v0.2:

1. **Witness model details** — Sigstore Rekor-style transparency, or
   gossip-only? Trade-off between operational simplicity and openness.
2. **Macaroons vs JWS for L4 v2** — caveat attenuation is desirable; how
   to migrate existing JWS holders?
3. **A2A interop level** — bridge protocol only, or also publish ATF
   identity bindings as A2A Agent Cards by default?
4. **Naming** — `agent-trust-fabric` is descriptive but unmemorable.
   Rebrand candidates evaluated at v0.3.
5. **Governance** — when (not if) ATF gains external adoption, what's
   the spec-evolution body? Linux Foundation / IETF / W3C / informal?

---

## 9. References

### Standards we build on

- A2A Protocol v1.0 (Linux Foundation, 2026 early)
- Anthropic MCP (Linux Foundation Agentic AI Foundation, 2025-12)
- JOSE: JWS (RFC 7515), JWA (RFC 7518)
- W3C DID Core 1.0
- SPIFFE / SVID
- Sigstore (Rekor transparency log)
- OAuth 2.0 + scopes
- OpenTelemetry GenAI semantic conventions

### Adjacent products surveyed

- Solace Agent Mesh (OSS; closest neighbor)
- Microsoft Agent Governance Toolkit (OSS, 2026-04)
- Salesforce Agent Fabric (proprietary)
- ServiceNow AI Agent Fabric (proprietary)
- Okta for AI Agents (2026-04 GA)
- AWS AgentCore Identity

### Inspirational design sources

- Addy Osmani — `agent-skills`, "Code Agent Orchestra",
  "Agent Harness Engineering" (lifecycle / verification-first thinking)
- Certificate Transparency — cross-witness gossip model
- SWIFT — neutral inter-bank infrastructure pattern

### Gap signals

- VentureBeat, "RSAC 2026: Agent identity frameworks — three gaps"
- arXiv 2505.12490 (improving A2A trust)
- NIST AI Agent Standards Initiative (2026-02 launch)
