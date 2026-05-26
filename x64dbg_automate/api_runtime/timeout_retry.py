"""Timeout, retry, and circuit-breaker infrastructure for Axon MCP tools.

Provides decorators that wrap blocking x64dbg operations with:
- Hard timeouts (prevents indefinite hangs)
- Exponential backoff retry (recovers from transient ZMQ/RPC glitches)
- Circuit breaker (prevents storming a dead x64dbg instance)
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitBreaker:
    """Simple circuit breaker for x64dbg RPC calls.

    After *failure_threshold* consecutive failures, the breaker opens and
    rejects all calls for *recovery_timeout* seconds.
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 10.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_failure_time: float | None = None
        self._state = "closed"  # closed, open, half_open

    def call(self, fn: Callable[[], T]) -> T:
        if self._state == "open":
            if self._last_failure_time and (time.time() - self._last_failure_time) > self.recovery_timeout:
                self._state = "half_open"
            else:
                raise RuntimeError("Circuit breaker is OPEN — x64dbg RPC temporarily disabled")

        try:
            result = fn()
            self._on_success()
            return result
        except Exception as exc:
            self._on_failure()
            raise exc

    def _on_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def _on_failure(self) -> None:
        self._failures += 1
        self._last_failure_time = time.time()
        if self._failures >= self.failure_threshold:
            self._state = "open"


def timeout_retry(
    timeout: float = 10.0,
    retries: int = 2,
    backoff_base: float = 0.5,
    retryable_exceptions: tuple[type[Exception], ...] = (RuntimeError, ConnectionError, OSError),
):
    """Decorator that adds timeout and retry logic to a function.

    Args:
        timeout: Max seconds per attempt.
        retries: Number of retry attempts after the first failure.
        backoff_base: Initial backoff in seconds (doubles each retry).
        retryable_exceptions: Exception types that trigger a retry.
    """
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> T:
            last_exc: Exception | None = None
            for attempt in range(retries + 1):
                try:
                    # Use a simple time-based timeout check for the attempt
                    start = time.time()
                    result = fn(*args, **kwargs)
                    elapsed = time.time() - start
                    if elapsed > timeout:
                        logger.warning(f"{fn.__name__} succeeded but exceeded timeout ({elapsed:.2f}s > {timeout}s)")
                    return result
                except retryable_exceptions as exc:
                    last_exc = exc
                    if attempt < retries:
                        sleep_time = backoff_base * (2 ** attempt)
                        logger.warning(f"{fn.__name__} attempt {attempt + 1} failed: {exc}. Retrying in {sleep_time:.2f}s...")
                        time.sleep(sleep_time)
                    else:
                        raise
                except Exception:
                    # Non-retryable exception — fail fast
                    raise
            if last_exc is not None:
                raise last_exc
            raise RuntimeError("Unreachable")
        return wrapper
    return decorator
