import logging
import sys
from dataclasses import dataclass
from re import match
from typing import List, Union, Tuple

from bincopy import BinFile

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.core.program_section import ProgramSection
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class Ihex(GenericBinary):
    """
    Intel HEX is a binary blob packaging format encoded in ASCII. It splits binary data into records,
    which are lines of ASCII representing in hex the byte count, address, type, checksums of stored data.
    It is typically used for flashing firmware.

    # printf "Hello world!" | bin2hex.py -
    :0C00000048656C6C6F20776F726C642197
    :00000001FF
    """


@dataclass
class IhexProgram(Program):
    address_limits: Range
    start_addr: Union[None, int]
    segments: List[Range]


class IhexAnalyzer(Analyzer[None, Ihex]):
    """
    Extract Intel HEX parameters
    """

    targets = (IhexProgram,)
    outputs = (IhexProgram,)

    async def analyze(self, resource: Resource, config: None = None) -> IhexProgram:
        ihex_program, _ = _binfile_analysis(await resource.get_data())
        return ihex_program


class IhexUnpacker(Unpacker[None]):
    """
    Extract the Intel Hex image into a GenericBinary
    """

    targets = (Ihex, IhexProgram)
    children = (IhexProgram, ProgramSection)

    async def unpack(self, resource: Resource, config=None):
        if resource.has_tag(Ihex):
            ihex_program, binfile = _binfile_analysis(await resource.get_data())

            await resource.create_child_from_view(ihex_program, data=bytes(binfile.as_binary()))

        elif resource.has_tag(IhexProgram):
            ihex_program = await resource.view_as(IhexProgram)
            for seg in ihex_program.segments:
                segment_data_range = seg.translate(-ihex_program.address_limits.start)
                await resource.create_child_from_view(
                    ProgramSection(seg.start, seg.length()), data_range=segment_data_range
                )


class IhexPacker(Packer[None]):
    """
    Generate an Intel HEX file from an Ihex view
    """

    targets = (Ihex, IhexProgram)

    async def pack(self, resource: Resource, config=None) -> None:
        if resource.has_tag(IhexProgram):
            updated_segments = []
            min_vaddr = sys.maxsize
            max_vaddr = 0
            for segment_r in await resource.get_children_as_view(
                ProgramSection, r_filter=ResourceFilter.with_tags(ProgramSection)
            ):
                seg_length = await segment_r.resource.get_data_length()
                seg_start = segment_r.virtual_address
                updated_segments.append(Range.from_size(seg_start, seg_length))
                min_vaddr = min(min_vaddr, seg_start)
                max_vaddr = max(max_vaddr, seg_start + seg_length)
            ihex_prog = await resource.view_as(IhexProgram)
            ihex_prog.segments = updated_segments
            ihex_prog.address_limits = Range(min_vaddr, max_vaddr)
            resource.add_view(ihex_prog)

        elif resource.has_tag(Ihex):
            program_child = await resource.get_only_child_as_view(IhexProgram)
            vaddr_offset = -program_child.address_limits.start
            binfile = BinFile()
            binfile.execution_start_address = program_child.start_addr
            for seg in program_child.segments:
                seg_data = await resource.get_data(seg.translate(vaddr_offset))
                binfile.add_binary(seg_data, seg.start)

            new_data = binfile.as_ihex()
            if new_data.endswith("\n"):
                new_data = new_data[:-1]
            new_data = new_data.encode("utf-8")
            old_data_len = await resource.get_data_length()
            resource.queue_patch(Range(0, old_data_len), new_data)


class IhexIdentifier(Identifier):
    """
    Regex-test the entire resource to check if it satisfies intel-hex formatting
    """

    targets = (GenericText,)

    async def identify(self, resource: Resource, config=None) -> None:
        datalength = await resource.get_data_length()
        if datalength >= 10:
            data = await resource.get_data()
            if match(r"(\:([0-9A-F]{2}){5,})(\n|\r\n)+", data.decode("utf-8")):
                resource.add_tag(Ihex)


def _binfile_analysis(raw_ihex: bytes) -> Tuple[IhexProgram, BinFile]:
    binfile = BinFile()
    binfile.add_ihex(raw_ihex.decode("utf-8"))

    ihex_program = IhexProgram(
        Range(binfile.minimum_address, binfile.maximum_address),
        binfile.execution_start_address,
        [Range(segment.minimum_address, segment.maximum_address) for segment in binfile.segments],
    )
    return ihex_program, binfile
