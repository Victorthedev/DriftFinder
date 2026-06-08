import functools
import logging
import random
import time
from collections.abc import Callable
from typing import TypeVar

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")

RETRYABLE_ERROR_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "InternalError",
        "RequestTimeout",
    }
)


def aws_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple[type[Exception], ...] = (ClientError,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for AWS API calls with jittered exponential backoff.
    delay = min(base * 2^attempt + jitter, max_delay)

    Only retries on throttling and transient errors. Propagates all
    other ClientErrors immediately so callers can handle 404s etc.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> T:
            last_exc: Exception | None = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc

                    if isinstance(exc, ClientError):
                        code = exc.response["Error"]["Code"]
                        if code not in RETRYABLE_ERROR_CODES:
                            raise

                    if attempt == max_attempts - 1:
                        break

                    delay = min(
                        base_delay * (2**attempt) + random.uniform(0, 1),  # noqa: S311
                        max_delay,
                    )
                    logger.warning(
                        "AWS API call %s failed (attempt %d/%d), retrying in %.2fs. Error: %s",
                        func.__name__,
                        attempt + 1,
                        max_attempts,
                        delay,
                        exc,
                    )
                    time.sleep(delay)

            assert last_exc is not None
            raise last_exc

        return wrapper

    return decorator
