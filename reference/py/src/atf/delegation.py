"""L4 — Scoped Delegation Token.

Compact JWS (header.payload.signature). Algorithm is fixed to Ed25519
(`EdDSA`) at both signing and verification time to prevent algorithm
confusion. Claims are the ATF envelope:

    iss        delegator agent URI
    sub        delegatee agent URI
    scope      list of capabilities being delegated
    exp        expiry (unix seconds)
    nbf        not-before (unix seconds)
    iat        issued-at
    jti        unique token id (uuidv4)
    purpose    short human/agent-readable string
    constraints  arbitrary key/value structure (validated by delegatee)
    audit_uri  where the delegator publishes/accepts audit cross-signs
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._signing import sign_compact, verify_compact
from .errors import (
    TokenExpired,
    TokenInsufficientScope,
    TokenInvalidSignature,
    TokenNotYetValid,
)
from .manifest import manifest_has_capability

DEFAULT_TTL_SECONDS = 3600  # 1h
MAX_TTL_SECONDS = 86400  # 24h


@dataclass
class DelegationClaims:
    iss: str
    sub: str
    scope: list[str]
    exp: int
    nbf: int
    iat: int
    jti: str
    purpose: str
    constraints: dict[str, Any] = field(default_factory=dict)
    audit_uri: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "scope": self.scope,
            "exp": self.exp,
            "nbf": self.nbf,
            "iat": self.iat,
            "jti": self.jti,
            "purpose": self.purpose,
            "constraints": self.constraints,
            "audit_uri": self.audit_uri,
        }


def issue_token(
    *,
    delegator,  # Identity
    delegator_keypair,  # KeyPair (matching delegator)
    delegatee_id: str,
    scope: list[str],
    purpose: str,
    constraints: dict[str, Any] | None = None,
    expires_in: int = DEFAULT_TTL_SECONDS,
    audit_uri: str | None = None,
) -> str:
    """Issue a JWS-compact delegation token signed by the delegator."""

    if expires_in <= 0 or expires_in > MAX_TTL_SECONDS:
        raise ValueError(
            f"expires_in must be in (0, {MAX_TTL_SECONDS}]; got {expires_in}"
        )
    now = int(time.time())
    claims = DelegationClaims(
        iss=delegator.agent_id,
        sub=delegatee_id,
        scope=list(scope),
        exp=now + expires_in,
        nbf=now,
        iat=now,
        jti=f"tkn_{uuid.uuid4().hex}",
        purpose=purpose,
        constraints=constraints or {},
        audit_uri=audit_uri,
    )
    return sign_compact(claims.to_dict(), delegator_keypair)


def verify_token(
    token: str,
    *,
    delegator_public_key: Ed25519PublicKey,
    expected_sub: str,
    required_scope: str | None = None,
    delegator_manifest_content: dict[str, Any] | None = None,
    now: int | None = None,
) -> DelegationClaims:
    """Verify token signature, lifetime, subject, and scope.

    If `delegator_manifest_content` is provided, also check that every
    item in `scope` is actually declared in the delegator's manifest
    (delegator cannot delegate what it does not have).
    """

    try:
        _, payload = verify_compact(token, delegator_public_key)
    except Exception as e:
        raise TokenInvalidSignature(str(e)) from e

    now = now if now is not None else int(time.time())
    if now >= payload["exp"]:
        raise TokenExpired(f"expired at {payload['exp']}, now {now}")
    if now < payload["nbf"]:
        raise TokenNotYetValid(f"not yet valid until {payload['nbf']}")

    if payload["sub"] != expected_sub:
        raise TokenInsufficientScope(
            f"token sub {payload['sub']!r} does not match expected {expected_sub!r}"
        )

    if required_scope is not None and not _scope_covers(payload["scope"], required_scope):
        raise TokenInsufficientScope(
            f"required scope {required_scope!r} not in token scope {payload['scope']!r}"
        )

    if delegator_manifest_content is not None:
        for s in payload["scope"]:
            if not manifest_has_capability(delegator_manifest_content, s):
                raise TokenInsufficientScope(
                    f"delegator does not declare capability {s!r}"
                )

    return DelegationClaims(
        iss=payload["iss"],
        sub=payload["sub"],
        scope=list(payload["scope"]),
        exp=int(payload["exp"]),
        nbf=int(payload["nbf"]),
        iat=int(payload["iat"]),
        jti=str(payload["jti"]),
        purpose=str(payload["purpose"]),
        constraints=dict(payload.get("constraints") or {}),
        audit_uri=payload.get("audit_uri"),
    )


def _scope_covers(token_scopes: list[str], required: str) -> bool:
    """Hierarchical scope match — `code.write` covers `code.write.python`."""

    for s in token_scopes:
        if s == required:
            return True
        if required.startswith(s + "."):
            return True
    return False
