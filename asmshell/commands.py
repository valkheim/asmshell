import json
import logging
import os
import sys
from typing import Optional

from . import config, display, emulator, memory, registers, utils

logger = logging.getLogger(__name__)


def cmd_quit(_cmd: Optional[str] = None) -> None:
    """Quit the program"""
    sys.exit()


def cmd_clear(_cmd: Optional[str] = None) -> None:
    """Clear screen"""
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


def cmd_help(cmd: Optional[str] = None) -> None:
    """Shows the help"""
    if cmd is None:
        display.show_generic_help()
    else:
        display.show_command_help(cmd)


def cmd_registers(_cmd: Optional[str] = None) -> None:
    """Shows the registers"""
    display.show_registers()


def cmd_stack(_: Optional[str] = None) -> None:
    """Shows the stack"""
    display.show_stack()


def cmd_rb(cmd: str) -> None:
    """Read byte(s)

    .rb <va> <amount=1> -- Read <amount> byte(s) at address <addr>

    Example:
    > mov al, 0x10 ; mov bl, 'A' ; mov [al], bl
    > .rb 10
    0000000000000010: 41    |A               |
    > inc al ; mov bl, 'B' ; mov [al], bl
    > .rb 10 2
    0000000000000010: 41 42 |AB              |
    """
    memory.read_memory_chunks(cmd, 1)


def cmd_rw(cmd: str) -> None:
    """Read word(s)"""
    memory.read_memory_chunks(cmd, 2)


def cmd_rd(cmd: str) -> None:
    """Read double word(s)"""
    memory.read_memory_chunks(cmd, 4)


def cmd_rq(cmd: str) -> None:
    """Read double quad word(s)"""
    memory.read_memory_chunks(cmd, 8)


def cmd_rm(cmd: str) -> None:
    """Read memory

    .rm <va_start> <va_end> -- Read memory from <va_start> to <va_end>
    """
    if (range := utils.get_memory_range(cmd)) is None:
        return None

    mem = config.config.mu.mem_read(range.start, range.end)
    utils.hexdump(mem, base=range.start)


def cmd_wb(cmd: str) -> None:
    """Write byte(s)

    .wb <va> <byte(s)> -- Write <byte(s)> at address <va>
    """
    memory.write_memory_chunks(cmd)


def cmd_ri(cmd: str) -> None:
    """Read instruction(s)

    .ri -- Read instruction at the instruction pointer
    .ri <va> -- Read instruction at address <addr>
    .ri <va> <amount> -- Read <amount> instruction(s) at address <va>
    """
    cmd = utils.clean_str(cmd)
    options = cmd.split()
    try:
        virtual_address = int(
            utils.seq_get(options, 1)
            or config.config.mu.reg_read(registers.reg_get("rip"))
        )
        amount = int(utils.seq_get(options, 2) or 1)
    except ValueError:
        logging.exception("Cannot read command values")
        return None

    # 2.3.11 AVX Instruction Length
    # The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes.
    insn_max_length = 15
    offset = 0
    code = bytearray()
    for _ in range(amount):
        memory = config.config.mu.mem_read(
            virtual_address + offset, insn_max_length
        )
        i = next(config.config.md.disasm(memory, virtual_address + offset))
        offset += i.size
        code += i.bytes

    display.show_code(code, virtual_address)


def cmd_dump(cmd: str) -> None:
    """Dump emulator state to json file

    .dump <file.json>
    """
    options = utils.clean_str(cmd).split()
    state = emulator.get_state()
    if (filepath := utils.seq_get(options, 1)) is None:
        utils.ko(".dump <file.json>")
        print(json.dumps(state, indent=2))
    else:
        with open(filepath, "w") as fh:
            json.dump(state, fh, indent=2)


def cmd_decode(cmd: str) -> None:
    """Decode instruction

    .dec <va> -- Decode instruction at address <va>

    Example:
    > .wb 0 66 48 90
    > .dec
    Instruction details:
    mnemonic:     nop
    bytes:        0x66 0x48 0x90
    prefix:       0x00 0x00 0x66 0x00
    opcode:       0x90 0x00 0x00 0x00
    rex:          0x48
    addr size:    0x08
    modrm:        0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000)
    modrm offset: 0x00
    disp:         0x00
    sib:          0x00 (base: 0b000) (index: 0b000) (scale: 0b00)
    """
    options = cmd.split()
    virtual_address = int(
        utils.seq_get(options, 1)
        or config.config.mu.reg_read(registers.reg_get("rip"))
    )
    display.show_instruction(virtual_address)
