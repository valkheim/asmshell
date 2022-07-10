from keystone import *
from .config import config
from . import utils
from typing import List, Optional

def show_hexdump(asm_string: str, code: List[int]):
    print("", end=" ")
    for i in code:
        print(format(i, "02x"), end=" ")

    length = 2 * len(code) + len(code)
    spaces = min(32, 32 - length)
    print(" " * spaces, end=" | ")
    print(asm_string)


def assemble(asm_string: str) -> Optional[bytes]:
    try:
        for asm_insn in asm_string.split(";"):
            encoding, _ = config.ks.asm(asm_insn)
            show_hexdump(asm_insn, encoding)
            return bytes(encoding)
        
    except keystone.KsError as e:
        utils.ko(f"Cannot assemble {asm_string}")
        return None

