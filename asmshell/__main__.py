import logging
import os

from asmshell import activate_library_logger, commands, repl


def main() -> None:
    logging.getLogger(__name__).addHandler(
        activate_library_logger(logging.INFO, "%(message)s")
    )
    commands.cmd_help()
    session = repl.Repl()
    session.enable_history(
        os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history")
    )
    session.start()


if __name__ == "__main__":
    main()
