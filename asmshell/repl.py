import atexit
import logging
import os
import readline
from typing import Callable, List, Optional

from asmshell import utils

from . import assembler, config, display, emulator

logger = logging.getLogger(__name__)


class Repl:
    @staticmethod
    def __make_completer(
        vocabulary: List[str],
    ) -> Callable[[str, int], Optional[str]]:
        def custom_complete(text: str, state: int) -> str:
            results = [x for x in vocabulary if x.startswith(text)] + [None]
            return results[state]

        return custom_complete

    def __init__(
        self,
        prompt: str,
    ):
        self.prompt = prompt
        self.histfile = ""

        readline.set_completer(
            Repl.__make_completer(
                [
                    command_literal
                    for command_literals, _, _ in config.config.commands
                    for command_literal in command_literals
                ]
            )
        )
        readline.parse_and_bind("tab: complete")

    def enable_history(self, history_file: str) -> None:
        self.histfile = os.path.expanduser(history_file)
        try:
            readline.read_history_file(self.histfile)
        except FileNotFoundError:
            pass
        except PermissionError:
            self.histfile = ""
            logging.exception(
                f"Warning: You don't have permissions to read {history_file} and\n"
                "         the command history of this session won't be saved.\n"
                "         Either change this file's permissions, recreate it,\n"
                "         or use an alternate path with the SDB_HISTORY_FILE\n"
                "         environment variable."
            )
            return
        readline.set_history_length(1000)
        atexit.register(readline.write_history_file, self.histfile)

    def parse_internal_command(self, user_str: str) -> None:
        for commands, _, function in config.config.commands:
            if user_str.split()[0] in commands:
                function(user_str)

    def parse_asm(self, user_str: str) -> None:
        if (code := assembler.assemble(user_str)) is None:
            return

        display.show_code(code)
        emulator.emulate(code)
        display.show_separator()

    def parse(self, user_str: str) -> None:
        for user_cmd in user_str.split(";"):
            if not user_cmd:
                continue

            user_cmd = utils.clean_str(user_cmd)
            if len(user_cmd) > 1 and user_cmd[0] == ".":
                self.parse_internal_command(user_cmd)
            else:
                self.parse_asm(user_cmd)

    def start(self) -> None:
        while True:
            try:
                line = input(self.prompt).strip()
            except KeyboardInterrupt:  # Ctrl+C
                line = ""
                logger.info("")
            except (EOFError, SystemExit):  # Ctrl+D
                break

            if not line:
                continue

            self.parse(line)
