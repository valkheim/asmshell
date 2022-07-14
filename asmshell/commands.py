import os
import sys
from typing import Optional

from . import config, display, utils


def quit(cmd: Optional[str] = None) -> None:
    sys.exit()


def clear(cmd: Optional[str] = None) -> None:
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


def help(cmd: Optional[str] = None) -> None:
    print("Commands")
    for command_literals, description, _ in config.config.commands:
        grouped_commands = ", ".join(command_literals)
        padding = (20 - len(grouped_commands)) * " "
        print(f" {grouped_commands}: {padding}{description}")

    print()


def registers(cmd: Optional[str] = None) -> None:
    display.show_x86_64_registers()


def stack(cmd: Optional[str] = None) -> None:
    display.show_x86_64_stack()


def display_memory_range(cmd: str, length: int) -> None:
    range = utils.get_memory_range(cmd)
    range.end = range.start + length
    mem = config.config.mu.mem_read(range.start, range.end - range.start)
    utils.hexdump(mem, base=range.start)


def db(cmd: str) -> None:
    display_memory_range(cmd, 1)


def dw(cmd: str) -> None:
    display_memory_range(cmd, 2)


def dd(cmd: str) -> None:
    display_memory_range(cmd, 4)


def dq(cmd: str) -> None:
    display_memory_range(cmd, 8)
