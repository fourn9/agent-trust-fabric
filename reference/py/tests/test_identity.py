"""L0 Identity tests."""

import pytest

from atf import (
    ALG,
    Identity,
    IdentityError,
    KeyPair,
    parse_agent_uri,
    public_key_from_jwk,
)


def test_keypair_generate_and_jwk_roundtrip():
    kp = KeyPair.generate(kid="42")
    jwk = kp.public_jwk()
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["kid"] == "42"
    assert jwk["alg"] == ALG
    pk = public_key_from_jwk(jwk)
    # Sign with private, verify with reconstructed public
    sig = kp.private_key.sign(b"hello")
    pk.verify(sig, b"hello")


def test_pem_roundtrip():
    kp = KeyPair.generate(kid="9")
    pem = kp.private_pem()
    kp2 = KeyPair.from_pem(pem, kid="9")
    assert (
        kp.private_key.private_bytes_raw() == kp2.private_key.private_bytes_raw()
    )


def test_identity_agent_id_and_jwks():
    kp = KeyPair.generate(kid="1")
    ident = Identity(owner="example.com", name="claude", keypair=kp)
    assert ident.agent_id == "agent://example.com/claude#1"
    jwks = ident.jwks()
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == "1"


def test_parse_agent_uri_ok():
    o, n, k = parse_agent_uri("agent://example.com/claude#1")
    assert (o, n, k) == ("example.com", "claude", "1")


@pytest.mark.parametrize(
    "bad",
    [
        "https://example.com/claude#1",  # wrong scheme
        "agent://example.com/claude",  # no kid
        "agent://example.com#1",  # no name
    ],
)
def test_parse_agent_uri_rejects_malformed(bad: str):
    with pytest.raises(IdentityError):
        parse_agent_uri(bad)
