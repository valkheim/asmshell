import os

import asmshell.repl
import asmshell.utils

commands = {
    ".q": "Quit this program",
    ".quit": "Quit this program",
}


def welcome() -> None:
    print("Commands")
    for k, v in commands.items():
        padding = (10 - len(k)) * " "
        print(f" {k}: {padding}{v}")

    print()


def main() -> None:
    if "verbose":
        welcome()

    repl = asmshell.repl.Repl(commands.keys())
    repl.enable_history(os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history"))
    repl.start()


if __name__ == "__main__":
    main()
