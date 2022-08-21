from typing import Any, Dict

import unicorn

from asmshell import registers

from . import commands
from .config import config


def get_state() -> Dict[Any, Any]:
    state = {"registers": {}}
    for (k, v) in registers.init_registers().items():
        try:
            state["registers"][k] = config.mu.reg_read(v)
        except unicorn.unicorn.UcError:
            pass

    return state


def emulate(code: bytes) -> None:
    config.mu.mem_write(config.emu_base, code)
    config.mu.emu_start(config.emu_base, config.emu_base + len(code))
    config.emu_previous_mu.context_restore(config.emu_previous_ctx)
    commands.cmd_registers()
    commands.cmd_stack()
    config.emu_previous_ctx = config.mu.context_save()
