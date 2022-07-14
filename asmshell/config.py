import dataclasses

import capstone
import keystone
import unicorn
import unicorn.x86_const


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


@dataclasses.dataclass()
class Config(metaclass=Singleton):
    # postponed initialization, reducing this config module dependencies
    commands: object = dataclasses.field(init=False)

    ks: object = dataclasses.field(init=False)
    mu: object = dataclasses.field(init=False)
    emu_previous_mu: object = dataclasses.field(init=False)
    emu_previous_ctx: object = dataclasses.field(init=False)
    md: object = dataclasses.field(init=False)

    asm_arch: int = dataclasses.field(default=keystone.KS_ARCH_X86)
    asm_mode: int = dataclasses.field(default=keystone.KS_MODE_64)
    asm_syntax: int = dataclasses.field(default=keystone.KS_OPT_SYNTAX_INTEL)

    emu_arch: int = dataclasses.field(default=unicorn.UC_ARCH_X86)
    emu_mode: int = dataclasses.field(default=unicorn.UC_MODE_64)
    emu_base: int = dataclasses.field(default=0x0)
    emu_mem_size: int = dataclasses.field(default=0x1000 * 0x1000)  # 1 MiB

    md_arch: int = dataclasses.field(default=capstone.CS_ARCH_X86)
    md_mode: int = dataclasses.field(default=capstone.CS_MODE_64)

    def init_keystone(self):
        self.ks = keystone.Ks(self.asm_arch, self.asm_mode)
        self.ks.syntax = self.asm_syntax

    def init_unicorn(self):
        self.mu = unicorn.Uc(self.emu_arch, self.emu_mode)
        self.mu.mem_map(self.emu_base, self.emu_mem_size)
        self.mu.reg_write(
            unicorn.x86_const.UC_X86_REG_RSP, self.emu_base + 0x200000
        )
        self.emu_previous_mu = unicorn.Uc(self.emu_arch, self.emu_mode)
        self.emu_previous_ctx = self.mu.context_save()

    def init_capstone(self):
        self.md = capstone.Cs(self.md_arch, self.md_mode)
        self.md.detail = True

    def __post_init__(self):
        self.init_keystone()
        self.init_unicorn()
        self.init_capstone()


config = Config()
