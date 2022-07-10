from .config import config
from  . import display

def emulate(code: bytes):
    config.mu.mem_write(config.emu_base, code)
    config.mu.emu_start(config.emu_base, config.emu_base + len(code))
    display.show_x86_64_registers()
    display.show_x86_64_stack()