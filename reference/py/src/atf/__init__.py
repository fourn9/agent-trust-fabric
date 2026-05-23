"""agent-trust-fabric (ATF) — reference implementation."""

from .agent import Agent, PeerRecord
from .audit import AuditEvent, AuditLog, verify_record_signatures
from .delegation import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    DelegationClaims,
    issue_token,
    verify_token,
)
from .errors import (
    ATFError,
    AuditError,
    CrossSignFailed,
    DelegationError,
    IdentityError,
    ManifestError,
    ManifestInvalidSignature,
    OutcomeError,
    OutcomeInvalidSignature,
    OutcomeSchemaMismatch,
    TokenExpired,
    TokenInsufficientScope,
    TokenInvalidSignature,
    TokenNotYetValid,
    TokenReplay,
)
from .identity import ALG, Identity, KeyPair, parse_agent_uri, public_key_from_jwk
from .manifest import (
    Capability,
    Manifest,
    manifest_has_capability,
    sign_manifest,
    verify_manifest,
)
from .outcome import Outcome, sign_outcome, verify_outcome
from .wire import ATFClient, HandlerSpec, build_app

__version__ = "0.1.0"

__all__ = [
    "ALG",
    "ATFClient",
    "ATFError",
    "Agent",
    "AuditError",
    "AuditEvent",
    "AuditLog",
    "Capability",
    "CrossSignFailed",
    "DEFAULT_TTL_SECONDS",
    "DelegationClaims",
    "DelegationError",
    "HandlerSpec",
    "Identity",
    "IdentityError",
    "KeyPair",
    "MAX_TTL_SECONDS",
    "Manifest",
    "ManifestError",
    "ManifestInvalidSignature",
    "Outcome",
    "OutcomeError",
    "OutcomeInvalidSignature",
    "OutcomeSchemaMismatch",
    "PeerRecord",
    "TokenExpired",
    "TokenInsufficientScope",
    "TokenInvalidSignature",
    "TokenNotYetValid",
    "TokenReplay",
    "__version__",
    "build_app",
    "issue_token",
    "manifest_has_capability",
    "parse_agent_uri",
    "public_key_from_jwk",
    "sign_manifest",
    "sign_outcome",
    "verify_manifest",
    "verify_outcome",
    "verify_record_signatures",
    "verify_token",
]
