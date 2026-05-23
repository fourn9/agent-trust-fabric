"""L7 — Federated Audit Log (cross-signed events).

Each party (A, B) keeps its own SQLite log. A cross-agent event such as
``delegation.completed`` is recorded on both sides with **byte-identical
content** signed by both parties. The cross-sign protocol is:

1. B builds the event content (event_id, type, fields, ...) and signs it.
2. B stores its local record with one signature (B's). The record is
   marked ``pending_peer=True`` until A's signature arrives.
3. B returns content + B's signature inside the invoke response.
4. A verifies B's signature against the same canonical content bytes.
5. A signs the content with its own key and stores its local record with
   both signatures.
6. A (optionally) calls B's ``/atf/v1/audit/cosign`` endpoint to deliver
   A's signature so B can finalize its local record.

If step 6 never happens, B still holds its single-signed view of the event,
which is sufficient for detecting later tampering by A.

The chain hash is computed locally on each side over the canonical bytes
of the stored record (signatures included). It is therefore expected and
acceptable that A's and B's chain heads diverge — what matters is that
the per-event content bytes are identical.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._signing import canonical_json, sign_envelope, verify_envelope
from .errors import AuditError, CrossSignFailed

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    type TEXT NOT NULL,
    token_jti TEXT,
    prev_hash TEXT NOT NULL,
    record_json TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    pending_peer INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS events_token_jti ON events(token_jti);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""

GENESIS_HASH = "sha256:" + ("0" * 64)


@dataclass
class AuditEvent:
    """Cross-signable event content.

    The dict returned by :meth:`content` is what both parties sign.
    """

    type: str
    token_jti: str | None = None
    delegator_id: str | None = None
    delegatee_id: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex}")
    ts: int = field(default_factory=lambda: int(time.time()))

    def content(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.ts,
            "type": self.type,
            "token_jti": self.token_jti,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "fields": self.fields,
        }

    @classmethod
    def from_content(cls, content: dict[str, Any]) -> "AuditEvent":
        return cls(
            type=content["type"],
            token_jti=content.get("token_jti"),
            delegator_id=content.get("delegator_id"),
            delegatee_id=content.get("delegatee_id"),
            fields=dict(content.get("fields") or {}),
            event_id=content["event_id"],
            ts=int(content["ts"]),
        )


def _chain_hash(prev: str, record: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev.encode("ascii"))
    h.update(b"\n")
    h.update(canonical_json(record))
    return "sha256:" + h.hexdigest()


class AuditLog:
    """Per-agent local audit log (SQLite, append-only at the API level)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- introspection ----

    def latest_hash(self) -> str:
        with self._conn() as c:
            row = c.execute(
                "SELECT chain_hash FROM events ORDER BY ts DESC, event_id DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else GENESIS_HASH

    def has_jti(self, jti: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM events WHERE token_jti = ? LIMIT 1", (jti,)
            ).fetchone()
        return row is not None

    def get(self, event_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT record_json FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def all_events(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT record_json FROM events ORDER BY ts ASC, event_id ASC"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def pending_peer_count(self) -> int:
        with self._conn() as c:
            row = c.execute(
                "SELECT COUNT(*) FROM events WHERE pending_peer = 1"
            ).fetchone()
        return int(row[0]) if row else 0

    # ---- self-signed (single-party) events ----

    def append_self(
        self, event: AuditEvent, *, keypair, signer_id: str
    ) -> dict[str, Any]:
        content = event.content()
        sig = sign_envelope(content, keypair, signed_by=signer_id)
        record = {"content": content, "signatures": [sig]}
        self._insert(event, record, pending_peer=False)
        return record

    # ---- cross-signed events ----

    def sign_only(self, event: AuditEvent, *, keypair, signer_id: str) -> dict[str, Any]:
        """Sign the event without storing. Use when you are not the originator."""

        return sign_envelope(event.content(), keypair, signed_by=signer_id)

    def append_pending(
        self, event: AuditEvent, *, my_signature: dict[str, Any]
    ) -> dict[str, Any]:
        """Store an event signed only by self, awaiting peer cosign."""

        record = {"content": event.content(), "signatures": [my_signature]}
        self._insert(event, record, pending_peer=True)
        return record

    def append_finalized(
        self,
        event: AuditEvent,
        *,
        my_signature: dict[str, Any],
        peer_signature: dict[str, Any],
        peer_public_key: Ed25519PublicKey,
    ) -> dict[str, Any]:
        """Store a fully cross-signed event after verifying the peer's sig."""

        content = event.content()
        try:
            verify_envelope(content, peer_signature, peer_public_key)
        except Exception as e:
            raise CrossSignFailed(f"peer signature invalid: {e}") from e
        record = {
            "content": content,
            "signatures": [my_signature, peer_signature],
        }
        self._insert(event, record, pending_peer=False)
        return record

    def finalize_pending(
        self,
        event_id: str,
        *,
        peer_signature: dict[str, Any],
        peer_public_key: Ed25519PublicKey,
    ) -> dict[str, Any]:
        """Add the peer's signature to an existing pending record."""

        with self._conn() as c:
            row = c.execute(
                "SELECT record_json, pending_peer FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise AuditError(f"event {event_id!r} not found")
            if row[1] != 1:
                raise AuditError(f"event {event_id!r} is not pending peer signature")
            record = json.loads(row[0])
            try:
                verify_envelope(record["content"], peer_signature, peer_public_key)
            except Exception as e:
                raise CrossSignFailed(f"peer signature invalid: {e}") from e
            # Avoid duplicate signatures
            existing_signers = {s["signed_by"] for s in record["signatures"]}
            if peer_signature["signed_by"] not in existing_signers:
                record["signatures"].append(peer_signature)
            c.execute(
                "UPDATE events SET record_json = ?, pending_peer = 0 WHERE event_id = ?",
                (json.dumps(record, sort_keys=True, separators=(",", ":")), event_id),
            )
        return record

    # ---- private helpers ----

    def _insert(
        self,
        event: AuditEvent,
        record: dict[str, Any],
        *,
        pending_peer: bool,
    ) -> None:
        prev = self.latest_hash()
        chain = _chain_hash(prev, record)
        with self._conn() as c:
            c.execute(
                "INSERT INTO events(event_id, ts, type, token_jti, prev_hash, record_json, chain_hash, pending_peer) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.ts,
                    event.type,
                    event.token_jti,
                    prev,
                    json.dumps(record, sort_keys=True, separators=(",", ":")),
                    chain,
                    1 if pending_peer else 0,
                ),
            )


def verify_record_signatures(
    record: dict[str, Any],
    *,
    public_keys_by_signer: dict[str, Ed25519PublicKey],
) -> None:
    """Verify every signature attached to an audit record.

    Useful for third-party audit log inspection. Raises CrossSignFailed on
    the first failure.
    """

    content = record["content"]
    for sig in record.get("signatures", []):
        signer = sig.get("signed_by")
        pk = public_keys_by_signer.get(signer)
        if pk is None:
            raise CrossSignFailed(f"no public key provided for signer {signer!r}")
        try:
            verify_envelope(content, sig, pk)
        except Exception as e:
            raise CrossSignFailed(f"signature by {signer!r} invalid: {e}") from e
