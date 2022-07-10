from . import utils
from . import assemble
from . import emulate

def parse_internal_command(user_str: str):
    if user_str == ".q":
        utils.exit()

def parse_asm_line(user_str: str):
    if (machine_code := assemble.assemble(user_str)) is not None:
        emulate.emulate(machine_code)

def parse(user_str: str):
    if len(user_str) > 1 and user_str[0] == ".":
        parse_internal_command(user_str)
    else:
        parse_asm_line(user_str)