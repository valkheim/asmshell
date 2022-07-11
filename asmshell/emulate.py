from . import display
from .config import config


def emulate(code: bytes):
    config.mu.mem_write(config.emu_base, code)
    config.mu.emu_start(config.emu_base, config.emu_base + len(code))
    config.emu_previous_mu.context_restore(config.emu_previous_ctx)
    display.show_x86_64_registers()
    display.show_x86_64_stack()
    config.emu_previous_ctx = config.mu.context_save()
