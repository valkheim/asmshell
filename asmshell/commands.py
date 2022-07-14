import logging
import os
import sys
from typing import Optional

import unicorn

from . import config, display, utils

logger = logging.getLogger(__name__)


def quit(_cmd: Optional[str] = None) -> None:
    sys.exit()


def clear(_cmd: Optional[str] = None) -> None:
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


def help(_cmd: Optional[str] = None) -> None:
    logger.info(display.highlight("Commands:"))
    for command_literals, description, _ in config.config.commands:
        grouped_commands = ", ".join(command_literals)
        padding = (20 - len(grouped_commands)) * " "
        logger.info(f" {grouped_commands}: {padding}{description}")

    logger.info("")


def registers(_cmd: Optional[str] = None) -> None:
    display.show_x86_64_registers()


def stack(_: Optional[str] = None) -> None:
    display.show_x86_64_stack()


def display_memory_range(cmd: str, length: int) -> None:
    range = utils.get_memory_range(cmd)
    range.end = range.start + length
    mem = config.config.mu.mem_read(range.start, range.end - range.start)
    utils.hexdump(mem, base=range.start)


def db(cmd: str) -> None:
    """Display byte"""
    display_memory_range(cmd, 1)


def dw(cmd: str) -> None:
    """Display word"""
    display_memory_range(cmd, 2)


def dd(cmd: str) -> None:
    """Display double word"""
    display_memory_range(cmd, 4)


def dq(cmd: str) -> None:
    """Display double quad word"""
    display_memory_range(cmd, 8)


def di(cmd: str) -> None:
    """Display instruction(s)

    Examples:
    .di -- display instruction at the instruction pointer
    .di <va> -- display instruction at address <addr>
    .di <va> <amount> -- display <amount> instruction(s) at address <va>
    """
    cmd = utils.clean_str(cmd)
    options = cmd.split()
    virtual_address = int(
        utils.seq_get(options, 1)
        or config.config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
    )
    amount = int(utils.seq_get(options, 2) or 1)
    # 2.3.11 AVX Instruction Length
    # The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes.
    insn_max_length = 15
    offset = 0
    code = bytearray()
    for _ in range(amount):
        memory = config.config.mu.mem_read(
            virtual_address + offset, insn_max_length
        )
        i = next(config.config.md.disasm(memory, virtual_address + offset))
        offset += i.size
        code += i.bytes

    display.show_code(code, virtual_address)
