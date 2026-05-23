"""L1 Manifest tests."""

import pytest

from atf import (
    Capability,
    KeyPair,
    Manifest,
    ManifestInvalidSignature,
    manifest_has_capability,
    sign_manifest,
    verify_manifest,
)


def _manifest(agent_id="agent://findy.co.jp/coding#1") -> Manifest:
    return Manifest(
        agent_id=agent_id,
        version="0.1.0",
        capabilities=[
            Capability(name="code.read"),
            Capability(name="code.write.python"),
        ],
    )


def test_sign_verify_roundtrip():
    kp = KeyPair.generate()
    env = sign_manifest(_manifest(), kp)
    content = verify_manifest(env, kp.public_key)
    assert content["agent_id"] == "agent://findy.co.jp/coding#1"
    assert any(c["name"] == "code.read" for c in content["capabilities"])


def test_verify_detects_tamper():
    kp = KeyPair.generate()
    env = sign_manifest(_manifest(), kp)
    env["manifest"]["capabilities"].append({"name": "deploy.prod", "description": ""})
    with pytest.raises(ManifestInvalidSignature):
        verify_manifest(env, kp.public_key)


def test_verify_detects_wrong_key():
    kp = KeyPair.generate()
    other = KeyPair.generate()
    env = sign_manifest(_manifest(), kp)
    with pytest.raises(ManifestInvalidSignature):
        verify_manifest(env, other.public_key)


def test_capability_match_exact_and_hierarchical():
    content = {
        "capabilities": [
            {"name": "code.write"},
            {"name": "deploy.staging"},
        ]
    }
    assert manifest_has_capability(content, "code.write")
    assert manifest_has_capability(content, "code.write.python")
    assert manifest_has_capability(content, "deploy.staging")
    assert not manifest_has_capability(content, "deploy.prod")
    assert not manifest_has_capability(content, "code")  # not a prefix match
