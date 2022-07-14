import dataclasses
from typing import TypeVar

T = TypeVar("T")


@dataclasses.dataclass
class Range:
    start: int
    end: int
