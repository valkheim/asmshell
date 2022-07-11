from typing import Optional

import keystone

from . import typing, utils
from .config import config


def assemble(asm_string: str) -> Optional[typing.Code]:
    code = typing.Code()
    ba = bytearray()
    try:
        for asm_mnem in asm_string.split(";"):
            encoding, _ = config.ks.asm(asm_mnem)
            code.mnemonics.append(utils.clean_str(asm_mnem))
            code.instructions.append(encoding)
            ba += bytearray(encoding)

    except keystone.keystone.KsError:
        utils.ko(f"Cannot assemble {asm_string}")
        return None

    code.machine_code = bytes(ba)
    return code
