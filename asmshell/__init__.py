import logging

# https://docs.python.org/3/howto/logging.html#library-config
logging.getLogger(__name__).addHandler(logging.NullHandler())


# Helper to setup the logger for an application (as used in __name__.__main__.py)
def init_library_logger(
    level: int = logging.DEBUG,
    format: str = "%(asctime)s %(levelname)s %(message)s",
) -> logging.StreamHandler:
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(format))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.debug("Added a logging handler to logger: %s", __name__)
    return handler
