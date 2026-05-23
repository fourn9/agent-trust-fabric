"""L0 — Identity.

An ATF agent is identified by a URI:

    agent://<owner-domain>/<name>#<kid>

The owner publishes a JWK Set at a well-known URI. In MVP, identity keys
are Ed25519. The set of acceptable signing algorithms is fixed to a
single value to mitigate algorithm-confusion attacks against JWS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from ._b64 import b64url_decode, b64url_encode
from .errors import IdentityError

ALG = "EdDSA"  # JOSE alg for Ed25519 (RFC 8037)


def _agent_uri(owner: str, name: str, kid: str) -> str:
    return f"agent://{owner}/{name}#{kid}"


@dataclass
class KeyPair:
    """Ed25519 keypair plus a key id."""

    kid: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, kid: str = "1") -> "KeyPair":
        sk = Ed25519PrivateKey.generate()
        return cls(kid=kid, private_key=sk, public_key=sk.public_key())

    def public_jwk(self) -> dict[str, str]:
        raw = self.public_key.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(raw),
            "kid": self.kid,
            "alg": ALG,
            "use": "sig",
        }

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

    @classmethod
    def from_pem(cls, pem: bytes, kid: str = "1") -> "KeyPair":
        sk = load_pem_private_key(pem, password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise IdentityError("only Ed25519 keys are supported in MVP")
        return cls(kid=kid, private_key=sk, public_key=sk.public_key())


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise IdentityError("only OKP/Ed25519 keys accepted")
    raw = b64url_decode(jwk["x"])
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass
class Identity:
    """Public identity for an ATF agent."""

    owner: str
    name: str
    keypair: KeyPair
    attestations: list[dict[str, Any]] = field(default_factory=list)
    manifest_uri: str | None = None

    @property
    def agent_id(self) -> str:
        return _agent_uri(self.owner, self.name, self.keypair.kid)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.keypair.public_jwk()]}

    def jwks_uri(self, scheme: str = "https") -> str:
        return f"{scheme}://{self.owner}/.well-known/atf/{self.name}/jwks.json"

    def identity_document(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "jwks_uri": self.jwks_uri(),
            "owner_org": self.owner,
            "attestations": self.attestations,
            "manifest_uri": self.manifest_uri,
        }


def parse_agent_uri(uri: str) -> tuple[str, str, str]:
    """Return (owner, name, kid) from an agent:// URI."""

    if not uri.startswith("agent://"):
        raise IdentityError(f"not an agent URI: {uri}")
    rest = uri[len("agent://") :]
    if "#" not in rest:
        raise IdentityError(f"agent URI missing #kid: {uri}")
    body, kid = rest.split("#", 1)
    if "/" not in body:
        raise IdentityError(f"agent URI missing /name: {uri}")
    owner, name = body.split("/", 1)
    return owner, name, kid
