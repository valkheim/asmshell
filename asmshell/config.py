import dataclasses
from typing import Any, Dict, List

import capstone
import keystone
import unicorn
import unicorn.x86_const


class Singleton(type):
    _instances: Dict[Any, Any] = {}

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        if "renew" in kwargs and kwargs["renew"] is True:
            del kwargs["renew"]
            return super().__call__(*args, **kwargs)

        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


@dataclasses.dataclass()
class Config(metaclass=Singleton):
    # postponed initialization, reducing this config module dependencies
    commands: List[Any] = dataclasses.field(init=False)
    registers: Dict[str, Any] = dataclasses.field(init=False)
    mode: str = dataclasses.field(init=False)

    ks: keystone.Ks = dataclasses.field(init=False)
    mu: unicorn.Uc = dataclasses.field(init=False)
    emu_previous_mu: unicorn.Uc = dataclasses.field(init=False)
    emu_previous_ctx: Any = dataclasses.field(init=False)
    md: capstone.Cs = dataclasses.field(init=False)

    asm_arch: int = dataclasses.field(default=keystone.KS_ARCH_X86)
    asm_mode: int = dataclasses.field(init=False)
    asm_syntax: int = dataclasses.field(default=keystone.KS_OPT_SYNTAX_INTEL)

    emu_arch: int = dataclasses.field(default=unicorn.UC_ARCH_X86)
    emu_mode: int = dataclasses.field(init=False)
    emu_base: int = dataclasses.field(default=0x0)
    emu_mem_size: int = dataclasses.field(default=0x1000 * 0x1000)  # 1 MiB

    md_arch: int = dataclasses.field(default=capstone.CS_ARCH_X86)
    md_mode: int = dataclasses.field(init=False)

    def init_mode(self) -> None:
        if self.mode == "32":
            self.asm_mode = keystone.KS_MODE_32
            self.emu_mode = unicorn.UC_MODE_32
            self.md_mode = capstone.CS_MODE_32
        elif self.mode == "64":
            self.asm_mode = keystone.KS_MODE_64
            self.emu_mode = unicorn.UC_MODE_64
            self.md_mode = capstone.CS_MODE_64
        else:
            raise ValueError("bad mode")

    def init_keystone(self) -> None:
        self.ks = keystone.Ks(self.asm_arch, self.asm_mode)
        self.ks.syntax = self.asm_syntax

    def init_unicorn(self) -> None:
        self.mu = unicorn.Uc(self.emu_arch, self.emu_mode)
        self.mu.mem_map(self.emu_base, self.emu_mem_size)
        self.mu.reg_write(
            unicorn.x86_const.UC_X86_REG_RSP, self.emu_base + 0x200000
        )
        self.emu_previous_mu = unicorn.Uc(self.emu_arch, self.emu_mode)
        self.emu_previous_ctx = self.mu.context_save()

    def init_capstone(self) -> None:
        self.md = capstone.Cs(self.md_arch, self.md_mode)
        self.md.detail = True

    def init_registers(self) -> None:
        self.registers = {}
        for name in dir(unicorn.x86_const):
            if not name.startswith("UC_X86_REG_"):
                continue

            reg = name[11:].lower()
            self.registers[reg] = getattr(unicorn.x86_const, name)

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.init_mode()
        self.init_keystone()
        self.init_unicorn()
        self.init_capstone()
        self.init_registers()


config: Config = None  # type: ignore
