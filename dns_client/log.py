import logging
from contextlib import contextmanager
from typing import Iterator

LOGGER_NAME = __name__.split(".")[0]
logger = logging.getLogger(LOGGER_NAME)


@contextmanager
def disable_logger(name: str = LOGGER_NAME) -> Iterator[None]:
    logger = logging.getLogger(name)
    cur_value = logger.disabled
    logger.disabled = True
    try:
        yield
    finally:
        logger.disabled = cur_value
