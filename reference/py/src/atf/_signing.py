"""JWS-style signing primitives used by L1, L4, L6, L7.

Two forms are exposed:

* `sign_compact` / `verify_compact` — compact JWS (header.payload.signature)
  used by L4 Delegation Tokens (carried in HTTP headers).
* `sign_envelope` / `verify_envelope` — detached signature attached as a
  sibling JSON object, used by L1 Manifests, L6 Outcomes, and L7 Audit
  events.

Both forms enforce `alg=EdDSA` on the signing and verifying side to mitigate
algorithm-confusion attacks.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._b64 import b64url_decode, b64url_encode
from .errors import ATFError


ALG = "EdDSA"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization. Sorted keys, no whitespace, UTF-8.

    Sufficient for ATF MVP. Not full RFC 8785, but enough as long as both
    sides serialize through this same function.
    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign_compact(payload: dict, keypair) -> str:
    """Return JWS compact serialization."""

    header = {"alg": ALG, "kid": keypair.kid, "typ": "atf+jws"}
    header_b = b64url_encode(canonical_json(header))
    payload_b = b64url_encode(canonical_json(payload))
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    sig = keypair.private_key.sign(signing_input)
    return f"{header_b}.{payload_b}.{b64url_encode(sig)}"


def verify_compact(jws: str, public_key: Ed25519PublicKey) -> tuple[dict, dict]:
    """Verify a compact JWS. Returns (header, payload). Raises on failure."""

    try:
        header_b, payload_b, sig_b = jws.split(".")
    except ValueError as e:
        raise ATFError(f"malformed JWS: {e}") from e
    header = json.loads(b64url_decode(header_b))
    if header.get("alg") != ALG:
        raise ATFError(f"unsupported alg: {header.get('alg')!r}; expected {ALG}")
    payload = json.loads(b64url_decode(payload_b))
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    try:
        public_key.verify(b64url_decode(sig_b), signing_input)
    except InvalidSignature as e:
        raise ATFError("invalid signature") from e
    return header, payload


def sign_envelope(content: dict, keypair, signed_by: str) -> dict:
    """Sign `content` and return a signature envelope dict.

    Callers store the signature alongside the content; the canonical bytes
    of `content` (sorted JSON) are what gets signed.
    """

    signing_input = canonical_json(content)
    sig = keypair.private_key.sign(signing_input)
    return {
        "alg": ALG,
        "kid": keypair.kid,
        "signed_by": signed_by,
        "value": b64url_encode(sig),
    }


def verify_envelope(content: dict, signature: dict, public_key: Ed25519PublicKey) -> None:
    """Raise on bad signature; return silently on success."""

    if signature.get("alg") != ALG:
        raise ATFError(f"unsupported alg: {signature.get('alg')!r}; expected {ALG}")
    signing_input = canonical_json(content)
    try:
        public_key.verify(b64url_decode(signature["value"]), signing_input)
    except InvalidSignature as e:
        raise ATFError("invalid signature") from e
