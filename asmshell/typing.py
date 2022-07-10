from collections import namedtuple
from typing import List

class Code:
    mnemonics: List[str]
    instructions: List[bytes]
    machine_code: bytes

    def __init__(self):
        self.mnemonics = []
        self.instructions = []
        self.machine_code = b""
