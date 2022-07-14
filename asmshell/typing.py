import dataclasses
from typing import List, TypeVar

T = TypeVar("T")


class Code:
    mnemonics: List[str]
    instructions: List[bytes]
    machine_code: bytes

    def __init__(self):
        self.mnemonics = []
        self.instructions = []
        self.machine_code = b""


@dataclasses.dataclass
class Range:
    start: int
    end: int
