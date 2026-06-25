"""Read-only fixture path confinement for Phase 3 observations."""

from __future__ import annotations

from pathlib import Path

from .errors import UnsafeObservationError

_PRIVATE_SOURCE_PARTS = ("root", "new" + "basebot")
_PROJECT_EXAMPLE_ROOT = Path(__file__).resolve().parents[2] / "examples" / "scenarios" / "fixtures"


def validate_fixture_root(root: str | Path) -> Path:
    """Return an existing fixture root while rejecting private/server roots."""
    candidate = Path(root)
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    raw_parts = tuple(part.lower() for part in candidate.parts)
    if raw_parts[-2:] == _PRIVATE_SOURCE_PARTS:
        raise UnsafeObservationError("fixture root is prohibited")
    resolved = candidate.resolve(strict=True)
    parts = tuple(part.lower() for part in resolved.parts)
    if parts[-2:] == _PRIVATE_SOURCE_PARTS or resolved == Path("/"):
        raise UnsafeObservationError("fixture root is prohibited")
    if not resolved.is_dir():
        raise UnsafeObservationError("fixture root must be a directory")
    if not resolved.is_relative_to(Path("/tmp")) and resolved != _PROJECT_EXAMPLE_ROOT:
        raise UnsafeObservationError("fixture root must be an explicit fixture or temporary directory")
    return resolved


def resolve_fixture_path(root: str | Path, relative_path: str) -> Path:
    """Resolve a non-absolute fixture path without traversal or symlink escape."""
    fixture_root = validate_fixture_root(root)
    requested = Path(relative_path)
    if requested.is_absolute() or ".." in requested.parts:
        raise UnsafeObservationError("fixture path must be relative and confined")
    unresolved = fixture_root / requested
    try:
        resolved = unresolved.resolve(strict=True)
    except FileNotFoundError:
        parent = unresolved.parent.resolve(strict=True)
        if not parent.is_relative_to(fixture_root):
            raise UnsafeObservationError("fixture path escapes fixture root") from None
        return unresolved
    if not resolved.is_relative_to(fixture_root):
        raise UnsafeObservationError("fixture path escapes fixture root")
    return resolved
