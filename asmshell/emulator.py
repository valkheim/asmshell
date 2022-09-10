from typing import Any, Dict

import unicorn

from asmshell import commands, config, registers


def get_state() -> Dict[Any, Any]:
    state = {"registers": {}}
    for (k, v) in registers.init_registers().items():
        try:
            state["registers"][k] = config.config.mu.reg_read(v)
        except unicorn.unicorn.UcError:
            pass

    return state


def emulate(code: bytes) -> None:
    config.config.mu.mem_write(config.config.emu_base, code)
    config.config.mu.emu_start(
        config.config.emu_base, config.config.emu_base + len(code)
    )
    config.config.emu_previous_mu.context_restore(
        config.config.emu_previous_ctx
    )
    commands.cmd_registers()
    commands.cmd_stack()
    config.config.emu_previous_ctx = config.config.mu.context_save()
