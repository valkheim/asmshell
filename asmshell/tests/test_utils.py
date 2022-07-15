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
    def test_bit_is_set(self) -> None:
        value = 0b_10_10_10
        self.assertFalse(utils.isBitSet(value, 0))
        self.assertTrue(utils.isBitSet(value, 1))
        self.assertFalse(utils.isBitSet(value, 2))
        self.assertTrue(utils.isBitSet(value, 3))
        self.assertFalse(utils.isBitSet(value, 4))
        self.assertTrue(utils.isBitSet(value, 5))


class TestValues(unittest.TestCase):
    def test_parse_valid_hex_value(self) -> None:
        self.assertEqual(utils.parse_value("deadbeef"), 0xDEADBEEF)
        self.assertEqual(utils.parse_value("0xdeadbeef"), 0xDEADBEEF)
        self.assertEqual(utils.parse_value("0b101010", 2), 42)

    def test_parse_invalid_hex_value(self) -> None:
        self.assertNotEqual(utils.parse_value("0b101010"), bin(42))
        self.assertIsNone(utils.parse_value("not an address"))


class TestCollections(unittest.TestCase):
    def test_safe_seq_get(self) -> None:
        self.assertEqual(utils.seq_get(range(2), 0), 0)
        self.assertEqual(utils.seq_get(range(2), 1), 1)
        self.assertEqual(utils.seq_get(range(2), 2), None)


class TestMemory(unittest.TestCase):
    def test_get_partial_memory_range(self) -> None:
        range = utils.get_memory_range(".db 0010")
        self.assertIsNotNone(range)
        self.assertEqual(range.start, 0x10)
        self.assertEqual(range.end, None)

    def test_get_full_memory_range(self) -> None:
        range = utils.get_memory_range(".db 0010 0020")
        self.assertIsNotNone(range)
        self.assertEqual(range.start, 0x10)
        self.assertEqual(range.end, 0x20)

    def test_get_untidy_memory_range(self) -> None:
        range = utils.get_memory_range(".db 0020 0010")
        self.assertIsNone(range)
