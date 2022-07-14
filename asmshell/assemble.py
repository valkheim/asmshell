from typing import Optional

import keystone

from . import utils
from .config import config


def assemble(asm_string: str) -> Optional[bytes]:
    code = bytearray()
    try:
        for asm_mnem in asm_string.split(";"):
            if not asm_mnem:
                continue

            encoding, _ = config.ks.asm(asm_mnem)
            code += bytearray(encoding)

    except keystone.keystone.KsError:
        utils.ko(f"Cannot assemble {asm_string}")
        return None

    code = bytes(code)
    return code
