class TransientInfraError(Exception):
    """An infrastructure hiccup (database, object storage, Docker daemon, rule registry).

    The same scan may succeed if retried.
    """


class AnalysisError(Exception):
    """The scan itself failed (unsafe archive, analyzer crash or timeout).

    Retrying will not help; the message is shown to the user.
    """
