from . import utils
from . import assemble
from . import emulate
from . import display

def parse_internal_command(user_str: str):
    if user_str in [".q", ".quit"]:
        utils.exit()
    elif user_str in [".cls", ".clear"]:
        utils.clear()
    else:
        utils.ko("Unknow command")

def parse_asm(user_str: str):
    if (code := assemble.assemble(user_str)) is None:
        return

    display.show_code(code)
    emulate.emulate(code.machine_code)

def parse(user_str: str):
    if len(user_str) > 1 and user_str[0] == ".":
        parse_internal_command(user_str)
    else:
        parse_asm(user_str)