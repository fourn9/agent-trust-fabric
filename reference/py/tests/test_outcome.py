"""L6 Outcome tests."""

import pytest

from atf import (
    KeyPair,
    Outcome,
    OutcomeInvalidSignature,
    OutcomeSchemaMismatch,
    sign_outcome,
    verify_outcome,
)


def test_outcome_roundtrip():
    kp = KeyPair.generate()
    o = Outcome(
        token_jti="tkn_1",
        status="ok",
        payload={"image_url": "https://example.com/x.png"},
        schema_id="image.generate.v1",
    )
    env = sign_outcome(o, kp, signed_by="agent://example.com/image#1")
    content = verify_outcome(env, kp.public_key, expected_schema_id="image.generate.v1")
    assert content["status"] == "ok"
    assert content["payload"]["image_url"].startswith("https://")


def test_outcome_schema_mismatch_detected():
    kp = KeyPair.generate()
    o = Outcome(
        token_jti="tkn_1",
        status="ok",
        payload={"x": 1},
        schema_id="actual.v1",
    )
    env = sign_outcome(o, kp, signed_by="agent://x/y#1")
    with pytest.raises(OutcomeSchemaMismatch):
        verify_outcome(env, kp.public_key, expected_schema_id="expected.v1")


def test_outcome_signature_tamper_detected():
    kp = KeyPair.generate()
    o = Outcome(
        token_jti="tkn_1",
        status="ok",
        payload={"x": 1},
        schema_id="v1",
    )
    env = sign_outcome(o, kp, signed_by="agent://x/y#1")
    env["outcome"]["payload"]["x"] = 999  # tamper
    with pytest.raises(OutcomeInvalidSignature):
        verify_outcome(env, kp.public_key)


def test_outcome_hash_tamper_detected():
    """If someone changes the recorded hash to match a tampered payload but
    forgets to re-sign, signature check fails first. If they only tamper
    the hash, our hash-recompute step also catches it."""

    kp = KeyPair.generate()
    o = Outcome(
        token_jti="tkn_1",
        status="ok",
        payload={"x": 1},
        schema_id="v1",
    )
    env = sign_outcome(o, kp, signed_by="agent://x/y#1")
    # Forge a hash mismatch by replacing payload_hash but not the payload
    env["outcome"]["payload_hash"] = "sha256:" + "0" * 64
    # Signature was over the original content (correct hash), so verify_envelope
    # will fail before the hash-recompute check.
    with pytest.raises((OutcomeInvalidSignature, OutcomeSchemaMismatch)):
        verify_outcome(env, kp.public_key)
