import unittest

import capstone
import keystone
import unicorn

from asmshell import config


class TestConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_config: config.Config = config.Config("64", renew=True)  # type: ignore

    def test_config_module_provides_a_default_none_instance(self) -> None:
        self.assertIsNone(config.config)

    def test_config_instances(self) -> None:
        self.assertEqual(
            id(
                config.Config(
                    "64",
                )
            ),
            id(
                config.Config(
                    "64",
                )
            ),
        )
        self.assertNotEqual(
            id(self.sample_config), id(config.Config("64", renew=True))  # type: ignore
        )

    def test_config_32_cpu_mode_setup(self) -> None:
        cfg = config.Config("32", renew=True)
        self.assertEqual(cfg.asm_mode, keystone.KS_MODE_32)
        self.assertEqual(cfg.emu_mode, unicorn.UC_MODE_32)
        self.assertEqual(cfg.md_mode, capstone.CS_MODE_32)

    def test_config_64_cpu_mode_setup(self) -> None:
        cfg = config.Config("64", renew=True)
        self.assertEqual(cfg.asm_mode, keystone.KS_MODE_64)
        self.assertEqual(cfg.emu_mode, unicorn.UC_MODE_64)
        self.assertEqual(cfg.md_mode, capstone.CS_MODE_64)

    def test_config_bad_cpu_mode_setup(self) -> None:
        with self.assertRaises(ValueError) as cm:
            config.Config("bad_mode", renew=True)

        self.assertEqual(str(cm.exception), "bad mode")

    def test_config_has_assembler_instance(self) -> None:
        self.assertIsNotNone(self.sample_config.ks)

    def test_config_has_disassembler_instance(self) -> None:
        self.assertIsNotNone(self.sample_config.mu)

    def test_config_has_emulator_instance(self) -> None:
        self.assertIsNotNone(self.sample_config.mu)

    def test_config_has_registers(self) -> None:
        self.assertIsNotNone(self.sample_config.registers)
        self.assertNotEqual(self.sample_config.registers, {})
