import unittest

from asmshell import registers


class TestRegisters(unittest.TestCase):
    def test_init_registers(self) -> None:
        regs = registers.init_registers()
        self.assertIsNotNone(regs)
        for reg in ("rax", "cr0", "eflags", "gs"):
            with self.subTest(f"Test {reg}"):
                self.assertTrue(reg in regs)
