import unittest

from asmshell import registers


class TestRegisters(unittest.TestCase):
    def test_get_reg(self) -> None:
        for reg_name in ("rax", "cr0", "eflags", "gs"):
            with self.subTest(f"Test '{reg_name}'"):
                self.assertIsNotNone(registers.reg_get(reg_name))
