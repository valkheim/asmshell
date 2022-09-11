import unittest

from asmshell import config, memory


class TestMemoryRead(unittest.TestCase):
    def setUp(self) -> None:
        config.config = config.Config("64", renew=True)  # type: ignore

    def test_read_bytes(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb", 1), b"\x00")

    def test_read_byte_from_explicit_base_address(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb 0", 1), b"\x00")

    def test_read_bytes_from_explicit_base_address(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb 0 2", 1), b"\x00\x00")

    def test_read_bytes_with_larger_chunk_size(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb", 2), b"\x00\x00")
        self.assertEqual(
            memory.read_memory_chunks(".rb 0 2", 2), b"\x00\x00\x00\x00"
        )


class TestMemoryWrite(unittest.TestCase):
    def setUp(self) -> None:
        # Reset the config/state for each test
        memory.config.config = config.Config("64", renew=True)  # type: ignore

    def test_write_byte(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb", 1), b"\x00")
        self.assertEqual(memory.write_memory_chunks(".wb 0 ff"), b"\xff")
        self.assertEqual(memory.read_memory_chunks(".rb", 1), b"\xff")

    def test_write_bytes(self) -> None:
        self.assertEqual(memory.read_memory_chunks(".rb 0 2", 1), b"\x00\x00")
        self.assertEqual(memory.write_memory_chunks(".wb 0 ffff"), b"\xff\xff")
        self.assertEqual(memory.read_memory_chunks(".rb 0 2", 1), b"\xff\xff")
