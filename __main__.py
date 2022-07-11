import os

import asmshell.repl
import asmshell.utils

commands = {
    ".q": "Quit this program",
    ".quit": "Quit this program",
}


def welcome():
    print("Welcome to my asm shell")
    print("Commands")
    for k, v in commands.items():
        padding = (10 - len(k)) * " "
        print(f" {k}: {padding}{v}")


if "verbose":
    welcome()

repl = asmshell.repl.Repl(commands.keys())
repl.enable_history(os.getenv("ASMSHELL_HISTORY_FILE", "~/.asms_history"))
repl.start()
