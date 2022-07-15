from typing import Dict, Optional

import unicorn

from . import config


def init_registers() -> Dict[str, int]:
    return {
        "rax": unicorn.x86_const.UC_X86_REG_RAX,
        "rbx": unicorn.x86_const.UC_X86_REG_RBX,
        "rcx": unicorn.x86_const.UC_X86_REG_RCX,
        "rdx": unicorn.x86_const.UC_X86_REG_RDX,
        "rdi": unicorn.x86_const.UC_X86_REG_RDI,
        "rsi": unicorn.x86_const.UC_X86_REG_RSI,
        "rbp": unicorn.x86_const.UC_X86_REG_RBP,
        "rsp": unicorn.x86_const.UC_X86_REG_RSP,
        "rip": unicorn.x86_const.UC_X86_REG_RIP,
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "r8": unicorn.x86_const.UC_X86_REG_R8,
        "r9": unicorn.x86_const.UC_X86_REG_R9,
        "r10": unicorn.x86_const.UC_X86_REG_R10,
        "r11": unicorn.x86_const.UC_X86_REG_R11,
        "r12": unicorn.x86_const.UC_X86_REG_R12,
        "r13": unicorn.x86_const.UC_X86_REG_R13,
        "r14": unicorn.x86_const.UC_X86_REG_R14,
        "r15": unicorn.x86_const.UC_X86_REG_R15,
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ss": unicorn.x86_const.UC_X86_REG_SS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
    }


def reg_get(reg: str) -> Optional[int]:
    return config.config.registers.get(reg, None)
