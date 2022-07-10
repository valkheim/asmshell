import asmshell.shell
import asmshell.utils

def show_banner():
    print("Welcome to my asm shell")

show_banner()
while True:
    try:
        user_str = input("> ")
        asmshell.shell.parse(user_str)

    except KeyboardInterrupt:
        asmshell.utils.exit()

