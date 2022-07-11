import unicorn.x86_const

from . import typing, utils
from .config import config


def show_code(code: typing.Code):
    print("CODE:")
    rip = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
    for mnem, insn in zip(code.mnemonics, code.instructions):
        print(f"{rip:016x}", end=": ")
        for i in insn:
            print(format(i, "02x"), end=" ")

        length = 2 * len(insn) + len(insn)
        spaces = min(32, 32 - length)
        print(" " * spaces, end=" | ")
        print(mnem)
        rip += len(insn)


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
        f"rsp: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP):016x}"
        "    "
        f"rbp: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RBP):016x}"
        "\n"
        f"rip: {config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RIP):016x}"
    )


def show_x86_64_stack():
    print("STACK:")
    stack_ptr = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
    stack_mem = config.mu.mem_read(stack_ptr, 0x10 * 4)
    utils.hexdump(stack_mem, base=stack_ptr)
