"""L1 — Capability Manifest.

MVP form: the A2A Agent Card schema (adopted unchanged) wrapped in an ATF
signature envelope. An `evidence[]` array carries third-party capability
proofs and is included in the canonical bytes that are signed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._signing import sign_envelope, verify_envelope
from .errors import ManifestInvalidSignature


@dataclass
class Capability:
    name: str  # e.g. "code.write.python"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {"name": self.name, "description": self.description}
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class Manifest:
    """The content that gets signed (mirrors A2A Agent Card)."""

    agent_id: str
    version: str
    capabilities: list[Capability]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""
    homepage: str | None = None

    def to_content(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "description": self.description,
            "homepage": self.homepage,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "evidence": self.evidence,
        }


def sign_manifest(m: Manifest, keypair) -> dict[str, Any]:
    """Return a signed manifest envelope."""

    content = m.to_content()
    signature = sign_envelope(content, keypair, signed_by=m.agent_id)
    return {"manifest": content, "signature": signature}


def verify_manifest(envelope: dict[str, Any], public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify and return the manifest content. Raises on failure."""

    try:
        content = envelope["manifest"]
        signature = envelope["signature"]
    except KeyError as e:
        raise ManifestInvalidSignature(f"missing field {e}")
    try:
        verify_envelope(content, signature, public_key)
    except Exception as e:
        raise ManifestInvalidSignature(str(e)) from e
    return content


def manifest_has_capability(content: dict[str, Any], cap_name: str) -> bool:
    """Check whether the manifest declares `cap_name` (exact or via prefix).

    A capability `code.write` covers `code.write.python` (more specific
    requests). A capability `code.write.python` covers exactly that, not
    `code.write` (more general).
    """

    for c in content.get("capabilities", []):
        declared = c.get("name", "")
        if cap_name == declared:
            return True
        if cap_name.startswith(declared + "."):
            return True
    return False
