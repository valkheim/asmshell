import logging
from logging import NullHandler

from . import commands, config, registers

# https://docs.python.org/3/howto/logging.html#library-config
logging.getLogger(__name__).addHandler(NullHandler())

# Initialize commands
config.config.commands = [
    ((".h", ".help"), "This help", commands.cmd_help),
    ((".q", ".quit"), "Quit this program", commands.cmd_quit),
    ((".cls", ".clear"), "Clear screen", commands.cmd_clear),
    (
        (".r", ".reg", ".registers"),
        "Display registers",
        commands.cmd_registers,
    ),
    ((".s", ".stack"), "Display the stack", commands.cmd_stack),
    ((".db",), "Display byte values", commands.cmd_db),
    ((".dw",), "Display word values", commands.cmd_dw),
    ((".dd",), "Display double-word values", commands.cmd_dd),
    ((".dq",), "Display quad-word values", commands.cmd_dq),
    ((".dm",), "Display memory", commands.cmd_dm),
    ((".di",), "Display instructions", commands.cmd_di),
]

# Initialize registers
config.config.registers = registers.init_registers()


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
