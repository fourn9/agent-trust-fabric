"""High-level Agent API.

This module composes L0 Identity, L1 Manifest, L4 Delegation, L6 Outcome,
and L7 Audit into a single :class:`Agent` class. Wire transport lives in
``atf.wire``; the Agent itself is transport-agnostic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit import AuditEvent, AuditLog
from .delegation import DEFAULT_TTL_SECONDS, DelegationClaims, issue_token, verify_token
from .errors import ATFError, ManifestInvalidSignature, TokenReplay
from .identity import Identity, KeyPair, parse_agent_uri, public_key_from_jwk
from .manifest import Capability, Manifest, manifest_has_capability, sign_manifest, verify_manifest
from .outcome import Outcome, sign_outcome, verify_outcome


@dataclass
class PeerRecord:
    """A peer agent the local agent has met before."""

    agent_id: str
    public_key: Ed25519PublicKey
    manifest_content: dict[str, Any]


@dataclass
class Agent:
    identity: Identity
    keypair: KeyPair
    audit_log: AuditLog
    data_dir: Path
    manifest_envelope: dict[str, Any] | None = None
    peers: dict[str, PeerRecord] = field(default_factory=dict)

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    # ---- construction ----

    @classmethod
    def create(
        cls,
        *,
        name: str,
        owner: str,
        data_dir: str | Path | None = None,
        kid: str = "1",
    ) -> "Agent":
        """Create a fresh agent: keypair, identity, empty audit log."""

        base = Path(data_dir) if data_dir else Path.home() / ".atf" / f"{owner}.{name}"
        base.mkdir(parents=True, exist_ok=True)

        key_path = base / "private.pem"
        if key_path.exists():
            kp = KeyPair.from_pem(key_path.read_bytes(), kid=kid)
        else:
            kp = KeyPair.generate(kid=kid)
            key_path.write_bytes(kp.private_pem())
            key_path.chmod(0o600)

        identity = Identity(owner=owner, name=name, keypair=kp)
        audit = AuditLog(base / "audit.sqlite")

        agent = cls(
            identity=identity,
            keypair=kp,
            audit_log=audit,
            data_dir=base,
        )

        # Load manifest if previously published
        m_path = base / "manifest.json"
        if m_path.exists():
            agent.manifest_envelope = json.loads(m_path.read_text())

        return agent

    # ---- L1: capability manifest ----

    def publish_manifest(
        self,
        capabilities: list[str | Capability],
        *,
        version: str = "0.1.0",
        description: str = "",
    ) -> dict[str, Any]:
        caps: list[Capability] = []
        for c in capabilities:
            caps.append(Capability(name=c) if isinstance(c, str) else c)
        manifest = Manifest(
            agent_id=self.agent_id,
            version=version,
            capabilities=caps,
            description=description,
        )
        envelope = sign_manifest(manifest, self.keypair)
        self.manifest_envelope = envelope
        (self.data_dir / "manifest.json").write_text(
            json.dumps(envelope, sort_keys=True, indent=2, ensure_ascii=False)
        )
        return envelope

    def manifest_content(self) -> dict[str, Any] | None:
        return self.manifest_envelope["manifest"] if self.manifest_envelope else None

    # ---- Peer registration (L0 + L1) ----

    def register_peer(
        self,
        *,
        agent_id: str,
        jwk: dict[str, Any] | None = None,
        public_key: Ed25519PublicKey | None = None,
        manifest_envelope: dict[str, Any],
    ) -> PeerRecord:
        """Register a peer's identity and verify their manifest."""

        if public_key is None:
            if jwk is None:
                raise ATFError("must provide either jwk or public_key")
            public_key = public_key_from_jwk(jwk)
        try:
            content = verify_manifest(manifest_envelope, public_key)
        except ManifestInvalidSignature as e:
            raise ATFError(f"peer manifest signature invalid: {e}") from e
        if content["agent_id"] != agent_id:
            raise ATFError(
                f"manifest agent_id {content['agent_id']!r} != registered {agent_id!r}"
            )
        record = PeerRecord(
            agent_id=agent_id, public_key=public_key, manifest_content=content
        )
        self.peers[agent_id] = record
        return record

    def peer(self, agent_id: str) -> PeerRecord:
        try:
            return self.peers[agent_id]
        except KeyError:
            raise ATFError(f"unknown peer {agent_id!r}; call register_peer first")

    # ---- L4: delegation ----

    def issue_delegation(
        self,
        *,
        to: str,
        scope: list[str],
        purpose: str,
        constraints: dict[str, Any] | None = None,
        expires_in: int = DEFAULT_TTL_SECONDS,
    ) -> str:
        """Issue a delegation token. Records a `delegation.issued` self-signed event."""

        # Sanity: delegator may only delegate caps it declares
        if self.manifest_envelope is not None:
            content = self.manifest_content()
            for s in scope:
                if not manifest_has_capability(content, s):
                    raise ATFError(
                        f"cannot delegate {s!r}: not in own manifest"
                    )

        token = issue_token(
            delegator=self.identity,
            delegator_keypair=self.keypair,
            delegatee_id=to,
            scope=scope,
            purpose=purpose,
            constraints=constraints,
            expires_in=expires_in,
            audit_uri=f"local://{self.agent_id}",
        )
        # Self-signed journal: A records the issuance locally
        # Extract the JTI by lightly decoding the JWS payload
        from ._b64 import b64url_decode

        _, payload_b, _ = token.split(".")
        jti = json.loads(b64url_decode(payload_b))["jti"]
        self.audit_log.append_self(
            AuditEvent(
                type="delegation.issued",
                token_jti=jti,
                delegator_id=self.agent_id,
                delegatee_id=to,
                fields={"scope": scope, "purpose": purpose},
            ),
            keypair=self.keypair,
            signer_id=self.agent_id,
        )
        return token

    def verify_delegation(
        self,
        token: str,
        *,
        required_scope: str,
    ) -> DelegationClaims:
        """Verify an incoming token (as delegatee)."""

        # Pre-parse to find iss
        from ._b64 import b64url_decode

        _, payload_b, _ = token.split(".")
        iss = json.loads(b64url_decode(payload_b))["iss"]
        peer = self.peer(iss)

        # Replay protection
        from ._b64 import b64url_decode

        jti = json.loads(b64url_decode(payload_b))["jti"]
        if self.audit_log.has_jti(jti):
            # Check if this JTI was already used as a completed delegation
            # (issued JTIs from us are fine, but completed JTIs from peers are not)
            existing = [
                e for e in self.audit_log.all_events()
                if e["content"].get("token_jti") == jti
                and e["content"].get("type") in {"delegation.started", "delegation.completed"}
            ]
            if existing:
                # Record the replay attempt as evidence
                self.audit_log.append_self(
                    AuditEvent(
                        type="delegation.replay_attempt",
                        token_jti=jti,
                        delegator_id=iss,
                        delegatee_id=self.agent_id,
                        fields={},
                    ),
                    keypair=self.keypair,
                    signer_id=self.agent_id,
                )
                raise TokenReplay(f"jti {jti!r} already used")

        claims = verify_token(
            token,
            delegator_public_key=peer.public_key,
            expected_sub=self.agent_id,
            required_scope=required_scope,
            delegator_manifest_content=peer.manifest_content,
        )
        return claims

    # ---- L6: outcome ----

    def make_outcome(
        self,
        *,
        token_jti: str,
        status: str,
        payload: Any,
        schema_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        o = Outcome(
            token_jti=token_jti,
            status=status,  # type: ignore[arg-type]
            payload=payload,
            schema_id=schema_id,
            reason=reason,
        )
        return sign_outcome(o, self.keypair, signed_by=self.agent_id)

    def verify_outcome_envelope(
        self,
        envelope: dict[str, Any],
        *,
        from_peer: str,
        expected_schema_id: str | None = None,
    ) -> dict[str, Any]:
        peer = self.peer(from_peer)
        return verify_outcome(
            envelope,
            delegatee_public_key=peer.public_key,
            expected_schema_id=expected_schema_id,
        )

    # ---- L7: cross-signed delegation.completed ----

    def build_completion_event(
        self,
        *,
        claims: DelegationClaims,
        outcome_envelope: dict[str, Any],
    ) -> AuditEvent:
        outcome_content = outcome_envelope["outcome"]
        ev_type = "delegation.completed" if outcome_content["status"] == "ok" else "delegation.failed"
        return AuditEvent(
            type=ev_type,
            token_jti=claims.jti,
            delegator_id=claims.iss,
            delegatee_id=claims.sub,
            fields={
                "purpose": claims.purpose,
                "scope": claims.scope,
                "status": outcome_content["status"],
                "outcome_hash": outcome_content["payload_hash"],
                "schema_id": outcome_content["schema_id"],
            },
        )
