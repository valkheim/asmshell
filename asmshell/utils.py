import logging
import re
from typing import Optional, Sequence

from asmshell import config, registers, typing
from asmshell.typing import Range, T

logger = logging.getLogger(__name__)


def ok(s: str):
    logger.info(f"[+] {s}")


def ko(s: str):
    logger.info(f"[-] {s}")


def clean_str(s: str) -> str:
    s = re.sub(r"\s\s+", " ", s)
    s = s.strip().lower()
    return s


def hexdump(src, base=0x0, length=0x10, sep="."):
    FILTER = "".join(
        [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(0xFF)]
    )
    lines = []
    for c in range(0, len(src), length):
        chars = src[c : c + length]
        hex_ = " ".join(["{:02x}".format(x) for x in chars])
        if len(hex_) > 0x18:
            hex_ = "{} {}".format(hex_[:0x18], hex_[0x18:])

        printable = "".join(
            ["{}".format((x <= 0x7F and FILTER[x]) or sep) for x in chars]
        )
        logger.info(
            "{0:016x}: {1:{2}s} |{3:{4}s}|".format(
                c + base, hex_, length * 3, printable, length
            )
        )

    return lines


def isBitSet(n: int, bit_offset: int) -> bool:
    mask = 1 << bit_offset
    return (n & mask) != 0


def seq_get(seq: Sequence[T], idx: int) -> Optional[T]:
    try:
        return seq[idx]
    except IndexError:
        return None


def parse_value(addr: Optional[str], base: int = 16) -> Optional[int]:
    if addr is None:
        return None

    try:
        return int(addr, base)
    except ValueError:
        return None


def parse_variable(ptr: Optional[str]) -> Optional[int]:
    return config.config.mu.reg_read(registers.reg_get(ptr[1:]))


def parse_pointer(ptr: Optional[str]) -> Optional[int]:
    if ptr is None:
        return None

    if ptr[0] == "$":
        return parse_variable(ptr)

    return parse_value(ptr)


def get_memory_range(cmd: str) -> Optional[typing.Range]:
    cmd = clean_str(cmd)
    options = cmd.split()
    addr_range = Range(
        start=parse_value(seq_get(options, 1)),
        end=parse_value(seq_get(options, 2)),
    )
    if addr_range.start is None:
        ko("base address is missing to retrieve memory")
        return None

    if addr_range.end is not None and addr_range.end < addr_range.start:
        ko("bad addresses range")
        return None

    return addr_range
