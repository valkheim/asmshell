import logging
import os
from typing import Dict

from . import registers, utils
from .color import Color
from .config import config

logger = logging.getLogger(__name__)


def highlight(string: str) -> str:
    return f"{Color.BOLD}{Color.YELLOW}{string}{Color.END}"


def show_separator() -> None:
    size = os.get_terminal_size()
    logger.info("—" * size.columns)


def show_generic_help() -> None:
    logger.info(highlight("Commands:"))
    for command_literals, description, _ in config.commands:
        grouped_commands = ", ".join(command_literals)
        padding = (20 - len(grouped_commands)) * " "
        logger.info(f" {grouped_commands}: {padding}{description}")

    logger.info("")


def show_command_help(cmd: str) -> None:
    requested_command = utils.seq_get(cmd.split(), 1)
    for literals, _, function in config.commands:
        if requested_command not in literals:
            continue

        logger.info(function.__doc__)


def show_code(code: bytes, virtual_address: int = None) -> None:
    logger.info(highlight("Code:"))
    if virtual_address is None:
        virtual_address = config.mu.reg_read(registers.reg_get("rip"))

    for i in config.md.disasm(code, virtual_address):
        line = f"{i.address:016x}: "
        line += " ".join([f"{byte:02x}" for byte in i.bytes])
        line += " " * (max(0, 42 - len(line))) + " | "
        line += f"{i.mnemonic} {i.op_str}"
        logger.info(line)


def show_instruction(virtual_address: int = None) -> None:
    if virtual_address is None:
        virtual_address = config.mu.reg_read(registers.reg_get("rip"))

    logger.info(highlight("Instruction details:"))
    mem = config.mu.mem_read(virtual_address, 15)
    config.md.details = True
    insn = next(config.md.disasm(mem, 15))
    config.md.details = False
    line = [f"mnemonic:     {insn.mnemonic} {insn.op_str}"]
    code = " ".join([f"{b:#04x}" for b in insn.bytes])
    line += [f"bytes:        {code}"]
    line += [f"prefix:       {utils.as_hex(insn.prefix)}"]
    line += [f"opcode:       {utils.as_hex(insn.opcode)}"]
    line += [f"rex:          {insn.rex:#04x}"]
    line += [f"addr size:    {insn.addr_size:#04x}"]
    modrm = bin(insn.modrm)[2:].zfill(8)
    modrm_line = f"modrm:        {insn.modrm:#04x} "
    modrm_line += f"(mod: 0b{modrm[0:2]}) "
    modrm_line += f"(reg: 0b{modrm[2:5]}) "
    modrm_line += f"(rm: 0b{modrm[5:8]})"
    line += [modrm_line]
    line += [f"modrm offset: {insn.modrm_offset:#04x}"]
    line += [f"disp:         {insn.disp:#04x}"]
    sib_line = f"sib:          {insn.sib:#04x} "
    sib_line += f"(base: 0b{(insn.reg_name(insn.sib_base) or 0):>03b}) "
    sib_line += f"(index: 0b{(insn.reg_name(insn.sib_index) or 0):>03b}) "
    sib_line += f"(scale: 0b{(insn.reg_name(insn.sib_scale) or 0):>02b})"
    line += [sib_line]
    logger.info(os.linesep.join(line))


def get_x86_64_register(reg: int) -> str:
    new = config.mu.reg_read(reg)
    old = config.emu_previous_mu.reg_read(reg)
    if old != new:
        return f"{Color.RED}{new:016x}{Color.END}"
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
        config.mu.reg_read(registers.reg_get("eflags")),
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
        config.mu.reg_read(registers.reg_get("cr0")),
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
        config.mu.reg_read(registers.reg_get("cr4")),
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


def show_x86_64_registers() -> None:
    logger.info(highlight("Registers:"))
    logger.info(
        f"rax:    {get_x86_64_register(registers.reg_get('rax'))}  r8:  {get_x86_64_register(registers.reg_get('r8'))}  cs: {get_x86_64_register(registers.reg_get('cs'))}  cr0: {get_x86_64_register(registers.reg_get('cr0'))} {get_cr0_str()}\n"
        f"rbx:    {get_x86_64_register(registers.reg_get('rbx'))}  r9:  {get_x86_64_register(registers.reg_get('r9'))}  ss: {get_x86_64_register(registers.reg_get('ss'))}  cr1: {get_x86_64_register(registers.reg_get('cr1'))}\n"
        f"rcx:    {get_x86_64_register(registers.reg_get('rcx'))}  r10: {get_x86_64_register(registers.reg_get('r10'))}  ds: {get_x86_64_register(registers.reg_get('ds'))}  cr2: {get_x86_64_register(registers.reg_get('cr2'))}\n"
        f"rdx:    {get_x86_64_register(registers.reg_get('rdx'))}  r11: {get_x86_64_register(registers.reg_get('r11'))}  es: {get_x86_64_register(registers.reg_get('es'))}  cr3: {get_x86_64_register(registers.reg_get('cr3'))}\n"
        f"rdi:    {get_x86_64_register(registers.reg_get('rdi'))}  r12: {get_x86_64_register(registers.reg_get('r12'))}  fs: {get_x86_64_register(registers.reg_get('fs'))}  cr4: {get_x86_64_register(registers.reg_get('cr4'))} {get_cr4_str()}\n"
        f"rsi:    {get_x86_64_register(registers.reg_get('rsi'))}  r13: {get_x86_64_register(registers.reg_get('r13'))}  gs: {get_x86_64_register(registers.reg_get('gs'))}\n"
        f"rbp:    {get_x86_64_register(registers.reg_get('rbp'))}  r14: {get_x86_64_register(registers.reg_get('r14'))}\n"
        f"rsp:    {get_x86_64_register(registers.reg_get('rsp'))}  r15: {get_x86_64_register(registers.reg_get('r15'))}\n"
        f"rip:    {get_x86_64_register(registers.reg_get('rip'))}\n"
        f"eflags: {get_x86_64_register(registers.reg_get('eflags'))} {get_eflags_str()}"
    )


def show_x86_64_stack() -> None:
    logger.info(highlight("Stack:"))
    stack_ptr = config.mu.reg_read(registers.reg_get("rsp"))
    stack_mem = config.mu.mem_read(stack_ptr, 0x10 * 4)
    utils.hexdump(stack_mem, base=stack_ptr)
