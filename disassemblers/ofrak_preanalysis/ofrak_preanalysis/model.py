from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from ofrak import ResourceAttributes
from ofrak.core import Program
from ofrak_type import Range, InstructionSetMode


class MissingPreAnalysisError(BaseException):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class PreAnalysis(ResourceAttributes):
    complex_block_sizes: Dict[int, int]
    complex_block_info: [Dict[int, Tuple[str, Optional[InstructionSetMode]]]]
    basic_block_bounds: Dict[int, List[Range]]
    basic_block_info: Dict[int, Tuple[InstructionSetMode, bool, Optional[int]]]


class PreAnalyzedProgram(Program):
    pass
