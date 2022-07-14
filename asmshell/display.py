import os
from typing import Dict

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


def get_flags_str(reg: int, flags: Dict[int, str]) -> str:
    flags_str = []
    for k, v in flags.items():
        if utils.isBitSet(reg, k):
            flags_str.append(v)

    return "[ " + " ".join(flags_str) + " ]"


def get_eflags_str() -> str:
    return get_flags_str(
        config.mu.reg_read(unicorn.x86_const.UC_X86_REG_EFLAGS),
        {
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
        },
    )


def get_cr0_str() -> str:
    return get_flags_str(
        config.mu.reg_read(unicorn.x86_const.UC_X86_REG_CR0),
        {
            0: "PE",  # Protected Mode: If 1, system is in protected mode, else system is in real mode
            1: "MP",  # Monitor co-processor: interaction of WAIT/FWAIT instructions with TS flag in CR0
            2: "EM",  # Emulation: If set, no x87 floating-point unit present, if clear, x87 FPU present
            3: "TS",  # Task switched: Allows saving x87 task context upon a task switch only after x87 instruction used
            4: "ET",  # Extension type: On the 386, it allowed to specify whether the external math coprocessor was an 80287 or 80387
            5: "NE",  # Numeric error: Enable internal x87 floating point error reporting when set, else enables PC style x87 error detection
            16: "WP",  # Write protect: When set, the CPU can't write to read-only pages when privilege level is 0
            18: "AM",  # Alignment mask: Alignment check enabled if AM set, AC flag (in EFLAGS register) set, and privilege level is 3
            29: "NW",  # Not-write through: Globally enables/disable write-through caching
            30: "CD",  # Cache disable: Globally enables/disable the memory cache
            31: "PG",  # Paging: If 1, enable paging and use the § CR3 register, else disable paging.
        },
    )


def get_cr4_str() -> str:
    return get_flags_str(
        config.mu.reg_read(unicorn.x86_const.UC_X86_REG_CR4),
        {
            0: "VME",  # Virtual 8086 Mode Extensions  If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
            1: "PVI",  # Protected-mode Virtual Interrupts  If set, enables support for the virtual interrupt flag (VIF) in protected mode.
            2: "TSD",  # Time Stamp Disable: If set, RDTSC instruction can only be executed when in ring 0, otherwise RDTSC can be used at any privilege level.
            3: "DE",  # Debugging Extensions: If set, enables debug register based breaks on I/O space access.
            4: "PSE",  # Page Size Extension: If unset, page size is 4 KiB, else page size is increased to 4 MiB If PAE is enabled or the processor is in x86-64 long mode this bit is ignored.[2]
            5: "PAE",  # Physical Address Extension: If set, changes page table layout to translate 32-bit virtual addresses into extended 36-bit physical addresses.
            6: "MCE",  # Machine Check Exception: If set, enables machine check interrupts to occur.
            7: "PGE",  # Page Global Enabled: If set, address translations (PDE or PTE records) may be shared between address spaces.
            8: "PCE",  # Performance-Monitoring Counter enable: If set, RDPMC can be executed at any privilege level, else RDPMC can only be used in ring 0.
            9: "OSFXSR",  # Operating system support for FXSAVE and FXRSTOR instructions: If set, enables Streaming SIMD Extensions (SSE) instructions and fast FPU save & restore.
            10: "OSXMMEXCPT",  # Operating System Support for Unmasked SIMD Floating-Point Exceptions: If set, enables unmasked SSE exceptions.
            11: "UMIP",  # User-Mode Instruction Prevention: If set, the SGDT, SIDT, SLDT, SMSW and STR instructions cannot be executed if CPL > 0.[1]
            12: "LA57",  # 57-Bit Linear Addresses: If set, enables 5-Level Paging.[3][4]: 2–18
            13: "VMXE",  # Virtual Machine Extensions Enable: see Intel VT-x x86 virtualization.
            14: "SMXE",  # Safer Mode Extensions Enable: see Trusted Execution Technology (TXT)
            16: "FSGSBASE",  # Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
            17: "PCIDE",  # PCID Enable: If set, enables process-context identifiers (PCIDs).
            18: "OSXSAVE",  # XSAVE and Processor Extended States Enable
            20: "SMEP",  # Supervisor Mode Execution Protection Enable: If set, execution of code in a higher ring generates a fault.
            21: "SMAP",  # Supervisor Mode Access Prevention Enable: If set, access of data in a higher ring generates a fault.[6]
            22: "PKE",  # Protection Key Enable: See Intel 64 and IA-32 Architectures Software Developer’s Manual.
            23: "CET",  # Control-flow Enforcement Technology: If set, enables control-flow enforcement technology.[4]: 2–19
            24: "PKS",  # Enable Protection Keys for Supervisor-Mode Pages: If set, each supervisor-mode linear address is associated with a protection key when 4-level or 5-level paging is in use.[4]: 2–19
        },
    )


def show_x86_64_registers():
    print("REGISTERS:")
    print(
        f"rax:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RAX)}  r8:  {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R8)}  cs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CS)}  cr0: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CR0)} {get_cr0_str()}\n"
        f"rbx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RBX)}  r9:  {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R9)}  ss: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_SS)}  cr1: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CR1)}\n"
        f"rcx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RCX)}  r10: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R10)}  ds: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_DS)}  cr2: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CR2)}\n"
        f"rdx:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RDX)}  r11: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R11)}  es: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_ES)}  cr3: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CR3)}\n"
        f"rdi:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RDI)}  r12: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R12)}  fs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_FS)}  cr4: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_CR4)} {get_cr4_str()}\n"
        f"rsi:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RSI)}  r13: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R13)}  gs: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_GS)}\n"
        f"rbp:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RBP)}  r14: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R14)}\n"
        f"rsp:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RSP)}  r15: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_R15)}\n"
        f"rip:    {get_x86_64_register(unicorn.x86_const.UC_X86_REG_RIP)}\n"
        f"eflags: {get_x86_64_register(unicorn.x86_const.UC_X86_REG_EFLAGS)} {get_eflags_str()}"
    )


def show_x86_64_stack():
    print("STACK:")
    stack_ptr = config.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSP)
    stack_mem = config.mu.mem_read(stack_ptr, 0x10 * 4)
    utils.hexdump(stack_mem, base=stack_ptr)
