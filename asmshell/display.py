import os

import unicorn.x86_const
from colorama import Fore, Style

from . import typing, utils
from .config import config


def show_separator():
    size = os.get_terminal_size()
    print("—" * size.columns)


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


def get_x86_64_register(reg: int):
    new = config.mu.reg_read(reg)
    old = config.emu_previous_mu.reg_read(reg)
    if old != new:
        return f"{Fore.RED}{new:016x}{Style.RESET_ALL}"
    else:
        return f"{new:016x}"


def get_eflags_str():
    eflags = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_EFLAGS)
    flags = {
        0: "CF",  # Carry Flag: Set by arithmetic instructions which generate either a carry or borrow. Set when an operation generates a carry to or a borrow from a destination operand.
        2: "PF",  # Parity flag: Set by most CPU instructions if the least significant (aka the low-order bits) of the destination operand contain an even number of 1's.
        4: "AF",  # Adjust/Auxiliary Carry Flag: Set if there is a carry or borrow involving bit 4 of EAX. Set when a CPU instruction generates a carry to or a borrow from the low-order 4 bits of an operand. This flag is used for binary coded decimal (BCD) arithmetic.
        6: "ZF",  # Zero Flag: Set by most instructions if the result an operation is binary zero.
        7: "SF",  # Sign Flag: Most operations set this bit the same as the most significant bit (aka high-order bit) of the result. 0 is positive, 1 is negative.
        8: "TF",  # Trap/Trace Flag: Permits single stepping of programs. After executing a single instruction, the processor generates an internal exception 1. When Trap Flag is set by a program, the processor generates a single-step interrupt after each instruction. A debugging program can use this feature to execute a program one instruction at a time.
        9: "IF",  # Interrupt Enable Flag: when set, the processor recognizes external interrupts on the INTR pin. When set, interrupts are recognized and acted on as they are received. The bit can be cleared to turn off interrupt processing temporarily.
        10: "DF",  # Direction Flag: Set and cleared using the STD and CLD instructions. It is used in string processing. When set to 1, string operations process down from high addresses to low addresses. If cleared, string operations process up from low addresses to high addresses.
        11: "OF",  # Overflow Flag: Most arithmetic instructions set this bit, indicating that the result was too large to fit in the destination. When set, it indicates that the result of an operation is too large or too small to fit in the destination operand.
        12: "IOPL",  # Input/Output privilege level flags: Used in protected mode to generate four levels of security.
        13: "IOPL",  # Input/Output privilege level flags: Used in protected mode to generate four levels of security.
        14: "NT",  # Nested Task Flag: Used in protected mode. When set, it indicates that one system task has invoked another via a CALL Instruction, rather than a JMP.
        16: "RF",  # Resume Flag: Used by the debug registers DR6 and DR7. It enables you to turn off certain exceptions while debugging code.
        17: "VM",  # Virtual 8086 Mode flag: Permits 80386 to behave like a high speed 8086.
    }
    flags_str = []
    for k, v in flags.items():
        if utils.isBitSet(eflags, k):
            flags_str.append(v)

    return " ".join(flags_str)


def show_x86_64_registers():
    print("REGISTERS:")
    print(
        f"rax:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RAX)}  r8:  {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R8)}  cs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CS)}\n"
        f"rbx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RBX)}  r9:  {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R9)}  ss: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_SS)}\n"
        f"rcx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RCX)}  r10: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R10)}  ds: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_DS)}\n"
        f"rdx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RDX)}  r11: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R11)}  es: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_ES)}\n"
        f"rdi:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RDI)}  r12: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R12)}  fs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_FS)}\n"
        f"rsi:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RSI)}  r13: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R13)}  gs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_GS)}\n"
        f"rbp:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RBP)}  r14: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R14)}\n"
        f"rsp:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RSP)}  r15: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R15)}\n"
        f"rip:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RIP)}\n"
        f"eflags: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_EFLAGS)} [ {get_eflags_str()} ]"
    )


def show_x86_64_stack():
    print("STACK:")
    stack_ptr = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
    stack_mem = config.mu.mem_read(stack_ptr, 0x10 * 4)
    utils.hexdump(stack_mem, base=stack_ptr)
