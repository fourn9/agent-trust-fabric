"""L4 Delegation tests."""

import time

import pytest

from atf import (
    Identity,
    KeyPair,
    TokenExpired,
    TokenInsufficientScope,
    TokenInvalidSignature,
    TokenNotYetValid,
    issue_token,
    verify_token,
)


@pytest.fixture
def delegator():
    kp = KeyPair.generate(kid="1")
    ident = Identity(owner="example.com", name="coding", keypair=kp)
    return ident, kp


def test_issue_and_verify(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="blog illustration",
    )
    claims = verify_token(
        token,
        delegator_public_key=kp.public_key,
        expected_sub="agent://example.com/image#1",
        required_scope="image.generate",
    )
    assert claims.iss == ident.agent_id
    assert claims.scope == ["image.generate"]
    assert claims.purpose == "blog illustration"


def test_verify_rejects_wrong_subject(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="x",
    )
    with pytest.raises(TokenInsufficientScope):
        verify_token(
            token,
            delegator_public_key=kp.public_key,
            expected_sub="agent://attacker/x#1",
            required_scope="image.generate",
        )


def test_verify_rejects_insufficient_scope(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="x",
    )
    with pytest.raises(TokenInsufficientScope):
        verify_token(
            token,
            delegator_public_key=kp.public_key,
            expected_sub="agent://example.com/image#1",
            required_scope="deploy.prod",
        )


def test_verify_hierarchical_scope_match(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/coding#1",
        scope=["code.write"],
        purpose="x",
    )
    # code.write should cover code.write.python
    claims = verify_token(
        token,
        delegator_public_key=kp.public_key,
        expected_sub="agent://example.com/coding#1",
        required_scope="code.write.python",
    )
    assert claims.scope == ["code.write"]


def test_verify_rejects_expired(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="x",
        expires_in=1,
    )
    with pytest.raises(TokenExpired):
        verify_token(
            token,
            delegator_public_key=kp.public_key,
            expected_sub="agent://example.com/image#1",
            required_scope="image.generate",
            now=int(time.time()) + 5,
        )


def test_verify_rejects_tampered_signature(delegator):
    ident, kp = delegator
    other = KeyPair.generate()
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="x",
    )
    with pytest.raises(TokenInvalidSignature):
        verify_token(
            token,
            delegator_public_key=other.public_key,
            expected_sub="agent://example.com/image#1",
            required_scope="image.generate",
        )


def test_verify_rejects_algorithm_confusion(delegator):
    """Tampering the header to alg=none must be rejected."""

    import base64
    import json

    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["image.generate"],
        purpose="x",
    )
    header_b, payload_b, _ = token.split(".")
    header = json.loads(
        base64.urlsafe_b64decode(header_b + "=" * (-len(header_b) % 4))
    )
    header["alg"] = "none"
    new_header_b = (
        base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    bad_token = f"{new_header_b}.{payload_b}.AAAA"
    with pytest.raises(TokenInvalidSignature):
        verify_token(
            bad_token,
            delegator_public_key=kp.public_key,
            expected_sub="agent://example.com/image#1",
            required_scope="image.generate",
        )


def test_verify_with_manifest_check_rejects_uncovered_scope(delegator):
    ident, kp = delegator
    token = issue_token(
        delegator=ident,
        delegator_keypair=kp,
        delegatee_id="agent://example.com/image#1",
        scope=["deploy.prod"],
        purpose="x",
    )
    fake_manifest = {"capabilities": [{"name": "image.generate"}]}
    with pytest.raises(TokenInsufficientScope):
        verify_token(
            token,
            delegator_public_key=kp.public_key,
            expected_sub="agent://example.com/image#1",
            required_scope="deploy.prod",
            delegator_manifest_content=fake_manifest,
        )
