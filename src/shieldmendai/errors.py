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
