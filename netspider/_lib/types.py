"""Core type definitions shared across protocol testers."""

import threading
from enum import Enum


class FindingType(Enum):
    WEAK_PASSWORD = "weak_password"
    NO_AUTH = "no_auth"
    DEFAULT_PASSWORD = "default_password"
    OPEN_SERVICE = "open_service"


class NetworkError(Exception):
    """Raised by testers on transient socket/connection failures.
    Caught by _with_retry for retry with backoff."""
    pass


# Thread-local context: testers set finding type before returning True
_finding_ctx = threading.local()


def _set_finding_type(ftype: FindingType):
    _finding_ctx.result_type = ftype


def _get_finding_type() -> FindingType:
    return getattr(_finding_ctx, 'result_type', FindingType.WEAK_PASSWORD)


class ScanResult:
    """Wrapper returned by _with_retry. __bool__ gives backward compat."""
    __slots__ = ('success', 'finding_type')
    def __init__(self, success: bool, finding_type: FindingType = FindingType.WEAK_PASSWORD):
        self.success = success
        self.finding_type = finding_type
    def __bool__(self):
        return self.success
