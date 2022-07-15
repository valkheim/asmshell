import unittest

from asmshell import emulator


class TestEmulator(unittest.TestCase):
    def test_get_state(self) -> None:
        state = emulator.get_state()
        self.assertIsNotNone(state)
        self.assertTrue("registers" in state)
