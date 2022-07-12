import unittest

from asmshell import utils


class TestCleanStr(unittest.TestCase):
    def test_clean_is_successful(self) -> None:
        test_strings = [
            ("normal string", "normal string"),
            ("string\twith\ttabs", "string\twith\ttabs"),
            ("\ttabs\t", "tabs"),
            (" spaces ", "spaces"),
            ("  more  spaces  ", "more spaces"),
            (" pre", "pre"),
            ("post ", "post"),
        ]
        for got, expected in test_strings:
            with self.subTest(f"Test '{got}'"):
                self.assertEqual(utils.clean_str(got), expected)


class TestBits(unittest.TestCase):
    def test_bit_is_set(self):
        value = 0b_10_10_10
        self.assertFalse(utils.isBitSet(value, 0))
        self.assertTrue(utils.isBitSet(value, 1))
        self.assertFalse(utils.isBitSet(value, 2))
        self.assertTrue(utils.isBitSet(value, 3))
        self.assertFalse(utils.isBitSet(value, 4))
        self.assertTrue(utils.isBitSet(value, 5))
