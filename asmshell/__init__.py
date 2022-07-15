import logging
from logging import NullHandler

from . import commands, config

# https://docs.python.org/3/howto/logging.html#library-config
logging.getLogger(__name__).addHandler(NullHandler())

# Initialize commands
config.config.commands = [
    ((".h", ".help"), "This help", commands.help),
    ((".q", ".quit"), "Quit this program", commands.quit),
    ((".cls", ".clear"), "Clear screen", commands.clear),
    (
        (".r", ".reg", ".registers"),
        "Display registers",
        commands.registers,
    ),
    ((".s", ".stack"), "Display the stack", commands.stack),
    ((".db",), "Display byte values", commands.db),
    ((".dw",), "Display word values", commands.dw),
    ((".dd",), "Display double-word values", commands.dd),
    ((".dq",), "Display quad-word values", commands.dq),
    ((".dm",), "Display memory", commands.dm),
    ((".di",), "Display instructions", commands.di),
]


# Helper to setup the logger for an application (as used in __name__.__main__.py)
def activate_library_logger(
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
