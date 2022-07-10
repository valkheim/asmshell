import keystone
import unicorn
import unicorn.x86_const
import dataclasses


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


@dataclasses.dataclass()
class Config(metaclass=Singleton):
    ks: object = dataclasses.field(init=False)
    mu: object = dataclasses.field(init=False)

    asm_arch : int = dataclasses.field(default=keystone.KS_ARCH_X86)
    asm_mode : int = dataclasses.field(default=keystone.KS_MODE_64)
    asm_syntax: int = dataclasses.field(default=keystone.KS_OPT_SYNTAX_INTEL)

    emu_arch : int = dataclasses.field(default=unicorn.UC_ARCH_X86)
    emu_mode : int = dataclasses.field(default=unicorn.UC_MODE_64)
    emu_base : int = dataclasses.field(default=0x0)
    emu_mem_size : int = dataclasses.field(default=0x1000 * 0x1000) # 1 MiB

    #emu_code_size : int = dataclasses.field(default=2 * 0x1000 * 0x1000) # 2MiB (0x2000000)

    def init_keystone(self):
        self.ks = keystone.Ks(self.asm_arch, self.asm_mode)
        self.ks.syntax = self.asm_syntax

    def init_unicorn(self):
        self.mu = unicorn.Uc(self.emu_arch, self.emu_mode)
        self.mu.mem_map(self.emu_base, self.emu_mem_size)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, self.emu_base + 0x200000)

    def __post_init__(self):
        self.init_keystone()
        self.init_unicorn()

config = Config()