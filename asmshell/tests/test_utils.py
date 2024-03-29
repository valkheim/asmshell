import unittest
from typing import cast

from asmshell import utils
from asmshell.typing import Range


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

    def test_list_as_hex(self) -> None:
        self.assertEqual(utils.as_hex([]), "")
        self.assertEqual(utils.as_hex([0, 1, 10]), "0x00 0x01 0x0a")

    def test_get_bytes_sequence(self) -> None:
        self.assertEqual(utils.get_bytes_sequence("aabb"), b"\xaa\xbb")
        self.assertEqual(
            utils.get_bytes_sequence(["aa", "bb"]),
            b"\xaa\xbb",
        )
        self.assertEqual(utils.get_bytes_sequence("XX"), bytes())
        self.assertEqual(utils.get_bytes_sequence("1"), b"")


class TestMemory(unittest.TestCase):
    def test_get_partial_memory_range(self) -> None:
        range = utils.get_memory_range(".rb 0010")
        self.assertIsNone(range)

    def test_get_full_memory_range(self) -> None:
        range = cast(Range, utils.get_memory_range(".rb 0010 0020"))
        self.assertIsNotNone(range)
        self.assertEqual(range.start, 0x10)
        self.assertEqual(range.end, 0x20)

    def test_get_untidy_memory_range(self) -> None:
        range = utils.get_memory_range(".rb 0020 0010")
        self.assertIsNone(range)


class TestChunks(unittest.TestCase):
    def test_chunks(self) -> None:
        self.assertEqual(list(utils.chunks("", 2)), [])
        self.assertEqual(list(utils.chunks("a", 2)), ["a"])
        self.assertEqual(list(utils.chunks("abcd", 2)), ["ab", "cd"])
        self.assertEqual(list(utils.chunks("abc", 2)), ["ab", "c"])


class TestPtrSize(unittest.TestCase):
    def test_ptr_size_64(self) -> None:
        expected_64_ptr_size = 16
        self.assertEqual(utils.get_ptr_size(), expected_64_ptr_size)
