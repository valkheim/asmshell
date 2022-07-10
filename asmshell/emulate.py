from .config import config
import unicorn.x86_const
from  . import utils

def show_x86_64_registers():
    print("REGISTERS:")
    print(
        f"rax: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RAX):016x}"
        "    "
        f"rbx: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RBX):016x}"
        "\n"
        f"rcx: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX):016x}"
        "    "
        f"rdx: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RDX):016x}"
        "\n"
    )

def show_x86_64_stack():
    print("STACK:")
    stack_ptr = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
    stack_mem = config.mu.mem_read(stack_ptr, 0x10 * 4)
    utils.hexdump(stack_mem, base=stack_ptr)

def emulate(code: bytes):
    config.mu.mem_write(config.emu_base, code)
    config.mu.emu_start(config.emu_base, config.emu_base + len(code))
    show_x86_64_registers()
    show_x86_64_stack()
