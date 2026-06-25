"""Safe public exceptions."""


class ShieldMendAiError(Exception):
    """Base error for expected ShieldMendAi failures."""


class ConfigurationError(ShieldMendAiError):
    """Raised when configuration is invalid."""
