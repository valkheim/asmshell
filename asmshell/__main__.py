import argparse
import logging
import os

from asmshell import commands, config, init_library_logger, repl


def get_arguments() -> argparse.Namespace:
    """Parse CLI options"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="no logging mode"
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["32", "64"],
        help="32-bit / 64-bit mode",
        default="64",
    )
    return parser.parse_args()


def init_config(mode: str) -> None:
    config.config: config.Config = config.Config(mode)  # type: ignore


def init_commands() -> None:
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
        ((".rb",), "Read byte values", commands.cmd_rb),
        ((".rw",), "Read word values", commands.cmd_rw),
        ((".rd",), "Read double-word values", commands.cmd_rd),
        ((".rq",), "Read quad-word values", commands.cmd_rq),
        ((".rm",), "Read memory", commands.cmd_rm),
        ((".ri",), "Read instructions", commands.cmd_ri),
        ((".wb",), "Write byte values", commands.cmd_wb),
        ((".d", ".dump"), "Dump state to file", commands.cmd_dump),
        ((".dec", ".decode"), "Decode instruction", commands.cmd_decode),
    ]


def init_repl(quiet: bool) -> None:
    prompt: str = ""
    if not quiet:
        logging.getLogger(__name__).addHandler(
            init_library_logger(logging.INFO, "%(message)s")
        )
        commands.cmd_help()
        prompt = f"{config.config.mode}> "

    session = repl.Repl(prompt)
    session.enable_history(
        os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history")
    )
    session.start()


def main() -> None:
    args = get_arguments()
    init_config(args.mode)
    init_commands()
    init_repl(args.quiet)


if __name__ == "__main__":
    main()
