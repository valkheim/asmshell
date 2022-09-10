import unittest

from asmshell import config, emulator


class TestEmulator(unittest.TestCase):
    def setUp(self) -> None:
        config.config = config.Config("64", renew=True)

    def test_get_state(self) -> None:
        state = emulator.get_state()
        self.assertIsNotNone(state)
        self.assertTrue("registers" in state)
