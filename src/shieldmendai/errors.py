"""Safe public exceptions."""


class ShieldMendAiError(Exception):
    """Base error for expected ShieldMendAi failures."""


class ConfigurationError(ShieldMendAiError):
    """Raised when configuration is invalid."""


class ScenarioError(ShieldMendAiError):
    """Raised when simulation scenario data is invalid or unsafe."""


class AdapterError(ShieldMendAiError):
    """Raised when adapter registration or dispatch is invalid."""


class UnsafeObservationError(ShieldMendAiError):
    """Raised when an observation would cross a Phase 3 safety boundary."""


class RepairValidationError(ShieldMendAiError):
    """Raised when repair input is invalid or unsafe."""


class RepairAuthorizationError(ShieldMendAiError):
    """Raised when a denied or mismatched repair is presented for planning."""


class UnsafeRepairError(ShieldMendAiError):
    """Raised when a repair would cross the simulation-only boundary."""


class RecoveryValidationError(ShieldMendAiError):
    """Raised when deterministic recovery input or state is invalid."""


class RecoveryTransitionError(ShieldMendAiError):
    """Raised when a recovery lifecycle transition is invalid."""


class UnsafeRecoveryError(ShieldMendAiError):
    """Raised when recovery would cross the simulation-only boundary."""


class IncidentValidationError(ShieldMendAiError):
    """Raised when an incident record or retention input is invalid."""


class IncidentTransitionError(ShieldMendAiError):
    """Raised when an incident lifecycle transition is invalid."""


class UnsafeIncidentStoreError(ShieldMendAiError):
    """Raised when local incident storage would cross its fixture boundary."""


class NotificationValidationError(ShieldMendAiError):
    """Raised when notification configuration, routing, or templates are invalid."""


class UnsafeNotificationError(ShieldMendAiError):
    """Raised when notification handling would cross the simulation-only boundary."""


class InstallationValidationError(ShieldMendAiError):
    """Raised when an installation plan or manifest is invalid."""


class UnsafeSandboxError(ShieldMendAiError):
    """Raised when an installation sandbox is not safely confined."""


class InstallationConflictError(ShieldMendAiError):
    """Raised when installed fixture content conflicts with a safe operation."""
