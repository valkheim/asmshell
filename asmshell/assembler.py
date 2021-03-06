from typing import Optional

import keystone

from . import utils
from .config import config


def assemble(asm_string: str) -> Optional[bytes]:
    code = bytearray()
    try:

        encoding, _ = config.ks.asm(asm_string)
        code += bytearray(encoding)

    except keystone.keystone.KsError:
        utils.ko(f"Cannot assemble {asm_string}")
        return None

    code = bytes(code)
    return code
