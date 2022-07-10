from keystone import *
from .config import config
from . import utils
from typing import Optional
from . import typing

def assemble(asm_string: str) -> Optional[typing.Code]:
    code = typing.Code()
    ba = bytearray()
    try:
        for asm_mnem in asm_string.split(";"):
            encoding, _ = config.ks.asm(asm_mnem)
            code.mnemonics.append(utils.clean_str(asm_mnem))
            code.instructions.append(encoding)
            ba += bytearray(encoding)
        
    except keystone.KsError as e:
        utils.ko(f"Cannot assemble {asm_string}")
        return None

    code.machine_code = bytes(ba)
    return code
