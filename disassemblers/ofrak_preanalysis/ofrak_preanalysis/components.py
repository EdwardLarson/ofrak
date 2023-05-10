import asyncio
import json
from dataclasses import dataclass
from typing import Dict, List, Union, Optional

from ofrak import Analyzer, Resource, ResourceFilter, Unpacker
from ofrak.core import ComplexBlock, MemoryRegion, BasicBlock, CodeRegion
from ofrak.model.component_model import ComponentConfig
from ofrak_preanalysis.model import PreAnalysis, PreAnalyzedProgram, MissingPreAnalysisError
from ofrak_type import InstructionSetMode, Range, NotFoundError


@dataclass
class LoadPreAnalysisConfig(ComponentConfig):
    json: str

    @staticmethod
    def slurp(path: str) -> "LoadPreAnalysisConfig":
        with open(path) as f:
            d = f.read()
        return LoadPreAnalysisConfig(d)


class LoadPreAnalysisAnalyzer(Analyzer[LoadPreAnalysisConfig, PreAnalysis]):
    targets = ()  # Doesn't run automatically
    outputs = (PreAnalysis,)

    async def analyze(self, resource: Resource, config: LoadPreAnalysisConfig) -> PreAnalysis:
        loaded_attrs = json.loads(config.json)

        raw_complex_block_sizes: Dict[int, List[int]] = loaded_attrs.get("complex_block_bounds")
        raw_complex_block_info: Dict[int, List[str]] = loaded_attrs.get("complex_block_info")
        raw_basic_block_bounds: Dict[int, List[List[int]]] = loaded_attrs.get("basic_block_bounds")
        raw_basic_block_info: Dict[int, List[Union[str, bool, Optional[int]]]] = loaded_attrs.get(
            "basic_block_info"
        )

        resource.add_tag(PreAnalyzedProgram)

        return PreAnalysis(
            {cb_vaddr: cb_size for cb_vaddr, cb_size in raw_complex_block_sizes.items()},
            {
                cb_vaddr: (
                    cb_info[0],
                    InstructionSetMode[cb_info[1]] if cb_info[1] is not None else None,
                )
                for cb_vaddr, cb_info in raw_complex_block_info.items()
            },
            {
                cb_vaddr: [Range(bb_range[0], bb_range[1]) for bb_range in bb_ranges]
                for cb_vaddr, bb_ranges in raw_basic_block_bounds.items()
            },
            {
                bb_vaddr: (InstructionSetMode[bb_info[0]], bb_info[1], bb_info[2])
                for bb_vaddr, bb_info in raw_basic_block_info.items()
            },
        )


class PreAnalysisCodeRegionUnpacker(Unpacker[None]):
    targets = (CodeRegion,)
    children = (ComplexBlock,)

    async def unpack(self, resource: Resource, config: None) -> None:
        pre_analysis = await _get_pre_analysis(resource)
        mr = await resource.view_as(MemoryRegion)
        code_region_range = mr.vaddr_range()

        cbs = [
            MemoryRegion(cb_vaddr, cb_size)
            for cb_vaddr, cb_size in pre_analysis.complex_block_sizes.items()
            if cb_vaddr in code_region_range
        ]

        create_child_tasks = [
            mr.create_child_region(child_mr, additional_tags=(ComplexBlock,)) for child_mr in cbs
        ]

        await asyncio.gather(*create_child_tasks)


class PreAnalysisComplexBlockAnalyzer(Analyzer[None, ComplexBlock]):
    targets = (ComplexBlock,)
    outputs = (ComplexBlock,)

    async def analyze(self, resource: Resource, config: None) -> ComplexBlock:
        pre_analysis = await _get_pre_analysis(resource)
        mr = await resource.view_as(MemoryRegion)
        cb_info = pre_analysis.complex_block_info.get(mr.virtual_address)
        if cb_info is None:
            raise MissingPreAnalysisError()

        cb_name, _ = cb_info

        return ComplexBlock(
            mr.virtual_address,
            mr.size,
            cb_name,
        )


class PreAnalysisComplexBlockUnpacker(Unpacker[None]):
    targets = (ComplexBlock,)
    children = (BasicBlock,)

    async def unpack(self, resource: Resource, config: None) -> None:
        pre_analysis = await _get_pre_analysis(resource)
        mr = await resource.view_as(MemoryRegion)
        basic_block_bounds = pre_analysis.basic_block_bounds.get(mr.virtual_address)
        if basic_block_bounds is None:
            # TODO: If this component is running and no BB bounds are pre-analyzed, but cb info is,
            #  just create 1 BasicBlock child with the mode info
            raise MissingPreAnalysisError()

        create_child_tasks = [
            mr.create_child_region(
                MemoryRegion(bb_range.start, bb_range.length()), additional_tags=(BasicBlock,)
            )
            for bb_range in basic_block_bounds
        ]

        await asyncio.gather(*create_child_tasks)


class PreAnalysisBasicBlockAnalyzer(Analyzer[None, BasicBlock]):
    targets = (BasicBlock,)
    outputs = (BasicBlock,)

    async def analyze(self, resource: Resource, config: None) -> BasicBlock:
        pre_analysis = await _get_pre_analysis(resource)
        mr = await resource.view_as(MemoryRegion)
        bb_info = pre_analysis.basic_block_info.get(mr.virtual_address)
        if bb_info is None:
            raise MissingPreAnalysisError()

        bb_mode, bb_is_exit, bb_exit_vaddr = bb_info

        return BasicBlock(
            mr.virtual_address,
            mr.size,
            bb_mode,
            bb_is_exit,
            bb_exit_vaddr,
        )


async def _get_pre_analysis(resource: Resource) -> PreAnalysis:
    try:
        pre_analyzed_r = await resource.get_only_ancestor(
            ResourceFilter.with_tags(PreAnalyzedProgram)
        )
    except NotFoundError:
        raise MissingPreAnalysisError(
            "No pre-analyzed resource found! Make sure to run the LoadPreAnalysisAnalyzer."
        )
    if pre_analyzed_r.has_attributes(PreAnalysis):
        return pre_analyzed_r.get_attributes(PreAnalysis)
    else:
        raise MissingPreAnalysisError(
            "Found a resource marked as pre-analyzed, but no pre-analysis found on it! Make sure "
            "to load pre-analysis via the LoadPreAnalysisAnalyzer"
        )
