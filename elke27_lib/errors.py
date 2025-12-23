"""
E27 error contract for provisioning and runtime.

This module defines structured exceptions used by the E27 implementation.
Home Assistant (and other callers) should use these types to decide whether
to retry, re-auth, or initiate provisioning.

Aligned decisions:
- DDR-0019: Provisioning vs Runtime Responsibilities and Module Boundaries
- DDR-0020: api_link Provisioning Failure is Silent; Timeout is the Only Signal
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class E27ErrorCode(str, Enum):
    """Stable error codes for logging and external mapping."""
    PROVISIONING_REQUIRED = "provisioning_required"
    PROVISIONING_TIMEOUT = "provisioning_timeout"
    LINK_INVALID = "link_invalid"
    AUTH_FAILED = "auth_failed"
    PROTOCOL_ERROR = "protocol_error"
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"
    NOT_READY = "not_ready"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class E27ErrorContext:
    """
    Optional structured context for debugging/logging.

    Keep this safe for logs: do NOT include access codes, passphrases, PINs,
    raw decrypted payloads, or key material.
    """
    host: Optional[str] = None
    port: Optional[int] = None
    phase: Optional[str] = None  # e.g. "discovery", "api_link", "hello", "authenticate", "call"
    detail: Optional[str] = None  # short non-secret info
    seq: Optional[int] = None
    session_id: Optional[int] = None


class E27Error(RuntimeError):
    """
    Base exception for all E27-specific failures.

    `message` should be clear English suitable for logs.
    `code` is a stable identifier suitable for programmatic mapping.
    `context` should never contain secrets.
    """

    def __init__(
        self,
        message: str,
        *,
        code: E27ErrorCode = E27ErrorCode.INTERNAL_ERROR,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.code: E27ErrorCode = code
        self.context: Optional[E27ErrorContext] = context
        self.__cause__ = cause


class E27ProvisioningRequired(E27Error):
    """
    Raised when runtime operation requires link credentials (linkkey/linkhmac),
    but none are available.

    This is the expected signal for a Home Assistant provisioning / reauth flow.
    """

    def __init__(
        self,
        message: str = "Provisioning is required: missing E27 link credentials (linkkey/linkhmac).",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.PROVISIONING_REQUIRED,
            context=context,
            cause=cause,
        )


class E27ProvisioningTimeout(E27Error):
    """
    Raised when api_link provisioning fails due to silent non-response.

    Per DDR-0020, incorrect access code and/or passphrase (and some identity
    mismatches) may cause the panel to not respond at all.
    """

    def __init__(
        self,
        message: str = (
            "Provisioning failed: the panel did not respond to api_link within the timeout. "
            "Verify access code/passphrase and connectivity, then retry."
        ),
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.PROVISIONING_TIMEOUT,
            context=context,
            cause=cause,
        )


class E27LinkInvalid(E27Error):
    """
    Raised when stored link credentials appear invalid.

    Typical triggers:
    - hello response sk/shm decrypt fails (MAGIC mismatch / invalid plaintext)
    - consistent decrypt/parse failures using a stored linkkey
    """

    def __init__(
        self,
        message: str = (
            "Stored E27 link credentials appear invalid (unable to establish session keys). "
            "Re-provisioning may be required."
        ),
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.LINK_INVALID,
            context=context,
            cause=cause,
        )


class E27AuthFailed(E27Error):
    """
    Raised when authentication fails (e.g., incorrect PIN or access level denied).

    Prefer raising this only when an explicit authenticated response indicates failure
    (e.g., error_code != 0), not for timeouts.
    """

    def __init__(
        self,
        message: str = "Authentication failed (PIN rejected or insufficient privileges).",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.AUTH_FAILED,
            context=context,
            cause=cause,
        )


class E27ProtocolError(E27Error):
    """
    Raised for protocol-level violations.

    Examples:
    - CRC failures after deframing
    - invalid LENGTH fields
    - MAGIC mismatch after decrypt (schema-0)
    - malformed payloads that violate expected invariants
    """

    def __init__(
        self,
        message: str = "E27 protocol error.",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.PROTOCOL_ERROR,
            context=context,
            cause=cause,
        )


class E27TransportError(E27Error):
    """
    Raised for socket/transport failures.

    Examples:
    - connection refused
    - connection reset
    - broken pipe
    - network unreachable
    """

    def __init__(
        self,
        message: str = "E27 transport error (socket/connectivity failure).",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.TRANSPORT_ERROR,
            context=context,
            cause=cause,
        )


class E27Timeout(E27Error):
    """
    Raised for timeouts that are not specifically provisioning timeouts.

    Use for:
    - waiting for a response to an authenticated encrypted call
    - waiting for hello response during runtime
    """

    def __init__(
        self,
        message: str = "E27 operation timed out waiting for a response.",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.TIMEOUT,
            context=context,
            cause=cause,
        )


class E27NotReady(E27Error):
    """
    Raised when an operation is attempted before the session is ready.

    Example:
    - trying to send encrypted commands before hello/auth has completed
    """

    def __init__(
        self,
        message: str = "E27 session is not ready for this operation.",
        *,
        context: Optional[E27ErrorContext] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            code=E27ErrorCode.NOT_READY,
            context=context,
            cause=cause,
        )
