"""L7 Audit log tests."""

from pathlib import Path

import pytest

from atf import (
    AuditEvent,
    AuditLog,
    CrossSignFailed,
    KeyPair,
    verify_record_signatures,
)
from atf._signing import sign_envelope


def _log(tmp_path: Path, name: str) -> AuditLog:
    return AuditLog(tmp_path / f"{name}.sqlite")


def test_self_signed_append(tmp_path: Path):
    log = _log(tmp_path, "a")
    kp = KeyPair.generate()
    ev = AuditEvent(type="delegation.issued", token_jti="tkn_1", delegator_id="A", delegatee_id="B")
    rec = log.append_self(ev, keypair=kp, signer_id="A")
    assert len(rec["signatures"]) == 1
    assert log.all_events()[0]["content"]["event_id"] == ev.event_id


def test_cross_sign_finalize_pending(tmp_path: Path):
    """B's flow: store pending after signing, then peer (A) cosigns."""

    b_log = _log(tmp_path, "b")
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()

    event = AuditEvent(
        type="delegation.completed",
        token_jti="tkn_xyz",
        delegator_id="A",
        delegatee_id="B",
        fields={"status": "ok"},
    )
    b_sig = sign_envelope(event.content(), kp_b, signed_by="B")
    b_log.append_pending(event, my_signature=b_sig)
    assert b_log.pending_peer_count() == 1

    # A's signature comes in later
    a_sig = sign_envelope(event.content(), kp_a, signed_by="A")
    rec = b_log.finalize_pending(
        event.event_id,
        peer_signature=a_sig,
        peer_public_key=kp_a.public_key,
    )
    assert len(rec["signatures"]) == 2
    assert b_log.pending_peer_count() == 0


def test_cross_sign_rejects_wrong_peer_key(tmp_path: Path):
    b_log = _log(tmp_path, "b")
    kp_a = KeyPair.generate()
    attacker = KeyPair.generate()
    kp_b = KeyPair.generate()

    event = AuditEvent(type="delegation.completed", token_jti="tkn", delegator_id="A", delegatee_id="B")
    b_sig = sign_envelope(event.content(), kp_b, signed_by="B")
    b_log.append_pending(event, my_signature=b_sig)

    # A signs, but we provide attacker's pubkey for verification
    a_sig = sign_envelope(event.content(), kp_a, signed_by="A")
    with pytest.raises(CrossSignFailed):
        b_log.finalize_pending(
            event.event_id, peer_signature=a_sig, peer_public_key=attacker.public_key
        )


def test_finalized_record_passes_third_party_verification(tmp_path: Path):
    a_log = _log(tmp_path, "a")
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    event = AuditEvent(
        type="delegation.completed", token_jti="tkn", delegator_id="A", delegatee_id="B"
    )
    b_sig = sign_envelope(event.content(), kp_b, signed_by="B")
    my_sig = sign_envelope(event.content(), kp_a, signed_by="A")
    a_log.append_finalized(
        event,
        my_signature=my_sig,
        peer_signature=b_sig,
        peer_public_key=kp_b.public_key,
    )
    rec = a_log.get(event.event_id)
    verify_record_signatures(
        rec,
        public_keys_by_signer={"A": kp_a.public_key, "B": kp_b.public_key},
    )


def test_tampered_finalized_record_fails_verification(tmp_path: Path):
    a_log = _log(tmp_path, "a")
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    event = AuditEvent(
        type="delegation.completed", token_jti="tkn", delegator_id="A", delegatee_id="B"
    )
    b_sig = sign_envelope(event.content(), kp_b, signed_by="B")
    my_sig = sign_envelope(event.content(), kp_a, signed_by="A")
    a_log.append_finalized(
        event, my_signature=my_sig, peer_signature=b_sig, peer_public_key=kp_b.public_key
    )
    rec = a_log.get(event.event_id)
    rec["content"]["fields"]["tampered"] = True
    with pytest.raises(CrossSignFailed):
        verify_record_signatures(
            rec,
            public_keys_by_signer={"A": kp_a.public_key, "B": kp_b.public_key},
        )


def test_has_jti(tmp_path: Path):
    log = _log(tmp_path, "x")
    kp = KeyPair.generate()
    ev = AuditEvent(type="delegation.started", token_jti="tkn_99", delegator_id="A", delegatee_id="B")
    log.append_self(ev, keypair=kp, signer_id="B")
    assert log.has_jti("tkn_99")
    assert not log.has_jti("not_present")
