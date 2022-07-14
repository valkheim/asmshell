import os
import sys

from . import config, display


def quit() -> None:
    sys.exit()


def clear() -> None:
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


def help() -> None:
    print("Commands")
    for command_literals, description, _ in config.config.commands:
        grouped_commands = ", ".join(command_literals)
        padding = (20 - len(grouped_commands)) * " "
        print(f" {grouped_commands}: {padding}{description}")

    print()


def registers() -> None:
    display.show_x86_64_registers()


def stack() -> None:
    display.show_x86_64_stack()
