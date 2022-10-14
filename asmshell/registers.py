from typing import Optional

from . import config


def reg_get(reg: str) -> Optional[int]:
    return config.config.registers.get(reg, None)
