import dataclasses
from typing import Dict, List, Optional, TypeVar, Union

T = TypeVar("T")

Registers = Dict[str, Union[int, List[int]]]


@dataclasses.dataclass
class Range:
    start: Optional[int]
    end: Optional[int]
