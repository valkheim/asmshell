import os
import asmshell.cli
import asmshell.utils
import asmshell.repl

def show_banner():
    print("Welcome to my asm shell")

show_banner()

repl = asmshell.repl.Repl([".q"])
repl.enable_history(os.getenv('ASMSHELL_HISTORY_FILE', '~/.asms_history'))
repl.start()