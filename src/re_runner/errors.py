class AnalysisError(Exception):
    """An explained input, capability, or execution failure."""

    code = "analysis-error"
    retryable = False


class InvalidInput(AnalysisError):
    code = "invalid-input"


class BudgetExceeded(AnalysisError):
    code = "budget-exceeded"


class ScopeDenied(AnalysisError):
    code = "scope-denied"


class CapabilityMissing(AnalysisError):
    code = "capability-missing"


class IntegrityError(AnalysisError):
    code = "integrity-error"


class Cancelled(AnalysisError):
    code = "cancelled"


class Locked(AnalysisError):
    code = "run-locked"


class NetworkError(AnalysisError):
    code = "network-error"
    retryable = True

