"""ATF exception hierarchy."""


class ATFError(Exception):
    """Base class for all ATF errors."""


class IdentityError(ATFError):
    """Identity layer (L0) failure."""


class ManifestError(ATFError):
    """Manifest layer (L1) failure."""


class ManifestInvalidSignature(ManifestError):
    pass


class DelegationError(ATFError):
    """Delegation layer (L4) failure."""


class TokenExpired(DelegationError):
    pass


class TokenNotYetValid(DelegationError):
    pass


class TokenInsufficientScope(DelegationError):
    pass


class TokenInvalidSignature(DelegationError):
    pass


class TokenReplay(DelegationError):
    pass


class OutcomeError(ATFError):
    """Outcome layer (L6) failure."""


class OutcomeInvalidSignature(OutcomeError):
    pass


class OutcomeSchemaMismatch(OutcomeError):
    pass


class AuditError(ATFError):
    """Audit layer (L7) failure."""


class CrossSignFailed(AuditError):
    pass
