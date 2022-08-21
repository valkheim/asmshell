from typing import Dict, Optional

import unicorn

from . import config


def init_registers() -> Dict[str, int]:
    registers = {}
    for name in dir(unicorn.x86_const):
        if not name.startswith("UC_X86_REG_"):
            continue

        reg = name[11:].lower()
        registers[reg] = getattr(unicorn.x86_const, name)

    return registers


def reg_get(reg: str) -> Optional[int]:
    return config.config.registers.get(reg, None)
