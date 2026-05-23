"""L6 — Outcome Verification (minimal).

An outcome is what the delegatee returns to the delegator. It is signed
by the delegatee. The payload's SHA-256 hash is recorded so that audit
events can reference it without storing the payload itself (privacy).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._signing import sign_envelope, verify_envelope
from .errors import OutcomeInvalidSignature, OutcomeSchemaMismatch

OutcomeStatus = Literal["ok", "error", "refused"]


@dataclass
class Outcome:
    token_jti: str
    status: OutcomeStatus
    payload: Any
    schema_id: str
    executed_at: int = field(default_factory=lambda: int(time.time()))
    reason: str | None = None

    def payload_hash(self) -> str:
        import json

        canonical = json.dumps(
            self.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def to_content(self) -> dict[str, Any]:
        return {
            "token_jti": self.token_jti,
            "status": self.status,
            "payload": self.payload,
            "payload_hash": self.payload_hash(),
            "schema_id": self.schema_id,
            "executed_at": self.executed_at,
            "reason": self.reason,
        }


def sign_outcome(o: Outcome, keypair, signed_by: str) -> dict[str, Any]:
    content = o.to_content()
    signature = sign_envelope(content, keypair, signed_by=signed_by)
    return {"outcome": content, "signature": signature}


def verify_outcome(
    envelope: dict[str, Any],
    delegatee_public_key: Ed25519PublicKey,
    expected_schema_id: str | None = None,
) -> dict[str, Any]:
    """Verify the outcome signature and (optionally) the declared schema id.

    Returns the outcome content dict on success.
    """

    try:
        content = envelope["outcome"]
        signature = envelope["signature"]
    except KeyError as e:
        raise OutcomeInvalidSignature(f"missing field {e}")

    try:
        verify_envelope(content, signature, delegatee_public_key)
    except Exception as e:
        raise OutcomeInvalidSignature(str(e)) from e

    if expected_schema_id is not None and content.get("schema_id") != expected_schema_id:
        raise OutcomeSchemaMismatch(
            f"expected schema {expected_schema_id!r}, got {content.get('schema_id')!r}"
        )

    # Verify hash matches payload
    o = Outcome(
        token_jti=content["token_jti"],
        status=content["status"],
        payload=content["payload"],
        schema_id=content["schema_id"],
        executed_at=content["executed_at"],
        reason=content.get("reason"),
    )
    if o.payload_hash() != content["payload_hash"]:
        raise OutcomeSchemaMismatch("payload_hash mismatch")

    return content
