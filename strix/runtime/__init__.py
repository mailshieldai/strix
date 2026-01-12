import logging
import os

from strix.config import Config

from .runtime import AbstractRuntime


logger = logging.getLogger(__name__)


class SandboxInitializationError(Exception):
    """Raised when sandbox initialization fails (e.g., Docker issues)."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


# Global runtime instance cache to prevent resource exhaustion
# Each runtime type maintains a single shared instance to avoid
# creating multiple Docker client connections
# Set STRIX_UNSAFE_MODE=true to disable connection pooling (not recommended)
_runtime_cache: dict[str, AbstractRuntime] = {}
_UNSAFE_MODE = os.getenv("STRIX_UNSAFE_MODE", "false").lower() == "true"

if _UNSAFE_MODE:
    logger.warning(
        "UNSAFE MODE - Docker connection pooling disabled! "
        "Each agent will create new Docker connections."
    )
else:
    logger.debug("Docker connection pooling enabled (shared client across agents)")


def get_runtime() -> AbstractRuntime:
    runtime_backend = Config.get("strix_runtime_backend")

    # In unsafe mode, create new connections every time (legacy behavior)
    if _UNSAFE_MODE:
        if runtime_backend == "docker":
            from .docker_runtime import DockerRuntime

            return DockerRuntime()  # New connection every time!

        raise ValueError(
            f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
        )

    # Safe mode: Return cached runtime instance if it exists to reuse connections
    if runtime_backend in _runtime_cache:
        return _runtime_cache[runtime_backend]

    if runtime_backend == "docker":
        from .docker_runtime import DockerRuntime

        runtime = DockerRuntime()
        _runtime_cache[runtime_backend] = runtime
        return runtime

    raise ValueError(
        f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
    )


def clear_runtime_cache() -> None:
    """Clear the runtime cache. Useful for testing or graceful shutdown."""
    _runtime_cache.clear()


__all__ = ["AbstractRuntime", "SandboxInitializationError", "get_runtime", "clear_runtime_cache"]
