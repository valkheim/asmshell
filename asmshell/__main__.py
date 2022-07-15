import argparse
import logging
import os

from asmshell import activate_library_logger, commands, repl


def get_arguments() -> argparse.Namespace:
    """Parse CLI options"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="no logging mode"
    )
    return parser.parse_args()


def main() -> None:
    args = get_arguments()
    prompt = ""
    if not args.quiet:
        logging.getLogger(__name__).addHandler(
            activate_library_logger(logging.INFO, "%(message)s")
        )
        commands.cmd_help()
        prompt = "> "

    session = repl.Repl(prompt)
    session.enable_history(
        os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history")
    )
    session.start()


if __name__ == "__main__":
    main()
