import logging
import re
from typing import Any, Iterator, List, Optional, Sequence, Union, cast

from asmshell import config, registers, typing
from asmshell.typing import Range, T

logger = logging.getLogger(__name__)


def ok(s: str) -> None:
    logger.info(f"[+] {s}")


def ko(s: str) -> None:
    logger.info(f"[-] {s}")


def clean_str(s: str) -> str:
    s = re.sub(r"\s\s+", " ", s)
    s = s.strip().lower()
    return s


def get_ptr_size() -> int:
    return int(config.config.mode) // 4


def hexdump(
    src: Sequence[Any],
    base: int = 0x0,
    length: int = 0x10,
    sep: str = ".",
    offset_size: int = 16,
) -> None:
    FILTER = "".join(
        [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(0xFF)]
    )
    for c in range(0, len(src), length):
        chars = src[c : c + length]
        hex_ = " ".join(["{:02x}".format(x) for x in chars])
        if len(hex_) > 0x18:
            hex_ = "{} {}".format(hex_[:0x18], hex_[0x18:])

        printable = "".join(
            ["{}".format((x <= 0x7F and FILTER[x]) or sep) for x in chars]
        )
        logger.info(
            "{0:0{5}x}: {1:{2}s} |{3:{4}s}|".format(
                c + base, hex_, length * 3, printable, length, offset_size
            )
        )


def isBitSet(n: int, bit_offset: int) -> bool:
    mask = 1 << bit_offset
    return (n & mask) != 0


def seq_get(seq: Sequence[T], idx: int) -> Optional[T]:
    try:
        return seq[idx]
    except IndexError:
        return None


def parse_value(value: Optional[str], base: int = 16) -> Optional[int]:
    if value is None:
        return None

    try:
        return int(value, base)
    except ValueError:
        return None


def parse_variable(ptr: Optional[str]) -> Optional[int]:
    if ptr is None:
        return None

    if (reg_id := registers.reg_get(ptr[1:])) is None:
        return None

    return cast(int, config.config.mu.reg_read(reg_id))


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
        ko("range start is missing")
        return None

    if addr_range.end is None:
        ko("range end is missing")
        return None

    if addr_range.end is not None and addr_range.end < addr_range.start:
        ko("bad range")
        return None

    return addr_range


def as_hex(xs: List[int]) -> str:
    return " ".join([f"{x:#04x}" for x in xs])


def chunks(xs: str, chunk_size: int = 2) -> Iterator[str]:
    i = 0
    while i < len(xs):
        yield xs[i : i + chunk_size]
        i += chunk_size


def get_bytes_sequence(data: Union[str, List[str]]) -> bytes:
    seq = "".join(data)
    if len(seq) % 2:
        ko(f"{seq} is not an even sequence, please pad with zeroes")
        return bytes()

    try:
        values: List[int] = []
        for x in chunks(seq, 2):
            if (value := parse_value(x)) is not None:
                values.append(value)

        return bytes(values)
    except TypeError:
        ko("bad bytes detected")
        return bytes()
