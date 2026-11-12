from __future__ import annotations


class CWOError(Exception):
    """Base exception for recoverable CWO library errors."""


class CWOValidationError(CWOError):
    """Raised when structured CWO input fails validation."""


class CWOPolicyError(CWOValidationError):
    """Raised when policy data is missing, inconsistent, or unsupported."""


class CWOPacketError(CWOValidationError):
    """Raised when contractor packet data fails validation."""


class CWOBoundaryError(CWOValidationError):
    """Raised when a share-boundary or disclosure rule is violated."""


class CWOBeadsError(CWOValidationError):
    """Raised when Beads-backed state cannot be read or validated."""


class UnknownExecutorError(SystemExit):
    """A requested executor is absent from a successfully loaded registry.

    This remains a SystemExit for compatibility with direct policy callers;
    malformed/unreadable policy and invalid alias graphs are not this category.
    """
