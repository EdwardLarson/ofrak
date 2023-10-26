import asyncio
import logging
import os
import re
import shutil
import tempfile
from subprocess import CalledProcessError
from typing import Dict, List, Optional, Tuple, Type, TextIO

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response

from ofrak import Resource
from ofrak.core import (
    ProgramAttributes,
    Program,
    SegmentInjectorModifier,
    SegmentInjectorModifierConfig,
    LinkableBinary,
)
from ofrak.gui.utils import OfrakShim, exceptions_to_http, json_response
from ofrak.service.error import SerializedError
from ofrak_patch_maker.model import BOM, PatchRegionConfig, PatchMakerException
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig, ToolchainException


class InvalidStateException(Exception):
    def __init__(self, current_step: str, missing_step: str):
        super().__init__(f"Could not {current_step}, required step ({missing_step}) not completed")


class PatchWizard:
    def __init__(self, shim: OfrakShim):
        self.patches: Dict[str, PatchInProgress] = {}
        self.helper: OfrakShim = shim

    def routes(self) -> List:
        return [
            web.post(
                "/{resource_id}/patch_wizard/start_new_patch",
                self.start_new_patch,
            ),
            web.post(
                "/patch_wizard/remove_patch",
                self.remove_patch,
            ),
            web.post(
                "/patch_wizard/add_file",
                self.add_file,
            ),
            web.post(
                "/patch_wizard/delete_file",
                self.delete_file,
            ),
            web.post(
                "/patch_wizard/get_object_infos",
                self.get_object_infos,
            ),
            web.post(
                "/patch_wizard/get_target_info",
                self.get_target_info,
            ),
            web.post("/patch_wizard/get_all_patches_in_progress", self.get_patches_in_progress),
            web.post("/patch_wizard/listen_logs", self.get_next_log_message),
            web.post("/{resource_id}/patch_wizard/save_current_patch", self.save_current_patch),
        ]

    @exceptions_to_http(SerializedError)
    async def start_new_patch(self, request: Request) -> Response:
        resource = await self.helper.get_resource_for_request(request)
        name = request.query.get("patch_name")
        patch = PatchInProgress(name, resource)
        self.patches[name] = patch

        return json_response(patch.latest_metadata)

    @exceptions_to_http(SerializedError)
    async def remove_patch(self, request: Request) -> Response:
        name = request.query.get("patch_name")
        del self.patches[name]

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def add_file(self, request: Request) -> Response:
        patch_name = request.query.get("patch_name")
        file_name = request.query.get("file_name")
        body = await request.read()
        self.patches[patch_name].files[file_name] = body

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def delete_file(self, request: Request) -> Response:
        patch_name = request.query.get("patch_name")
        file_name = request.query.get("file_name")

        del self.patches[patch_name].files[file_name]

        return Response(status=200)

    @exceptions_to_http(SerializedError)
    async def get_object_infos(self, request: Request) -> Response:
        patch_name = request.query.get("patch_name")
        patch_in_progress = self.patches[patch_name]

        body = await request.json()
        toolchain = self.helper.serializer.from_pjson(body["toolchain"], Type[Toolchain])
        toolchain_config = self.helper.serializer.from_pjson(
            body["toolchainConfig"], ToolchainConfig
        )

        patch_in_progress.latest_metadata["userInputs"]["toolchain"] = body["toolchain"]
        patch_in_progress.latest_metadata["userInputs"]["toolchainConfig"] = body["toolchainConfig"]

        patch_bom = await patch_in_progress.build_patch_bom(toolchain, toolchain_config)

        object_infos_struct = [
            {
                "name": os.path.basename(source_name),
                "segments": [
                    {
                        "name": seg.segment_name,
                        "size": seg.length,
                        "permissions": seg.access_perms.as_str(),
                        "include": False,
                        "allocatedVaddr": None,
                    }
                    for seg in obj.segment_map.values()
                ],
                "strongSymbols": list(obj.strong_symbols.keys()),
                "unresolvedSymbols": list(obj.unresolved_symbols.keys()),
            }
            for source_name, obj in patch_bom.object_map.items()
        ]

        return json_response(object_infos_struct)

    @exceptions_to_http(SerializedError)
    async def get_patches_in_progress(self, request: Request) -> Response:
        # Get all patches in progress, with populated patchInfos according to how much stuff is ready for each patch
        patches = [
            p.latest_metadata for p in self.patches.values() if p.latest_metadata is not None
        ]
        return json_response(patches)

    @exceptions_to_http(SerializedError)
    async def get_source_file_body(self, request: Request) -> Response:
        # Get the source file body for one patch
        raise NotImplementedError()

    @exceptions_to_http(SerializedError)
    async def get_target_info(self, request: Request) -> Response:
        patch_name = request.query.get("patch_name")
        patch_in_progress = self.patches[patch_name]

        target_bom, _ = await patch_in_progress.build_target_bom()

        symbols = set()
        for obj in target_bom.object_map.values():
            symbols.update(obj.strong_symbols)

        target_info_struct = {"symbols": list(symbols)}

        return json_response(target_info_struct)

    @exceptions_to_http(SerializedError)
    async def get_next_log_message(self, request: Request) -> Response:
        patch_name = request.query.get("patch_name")

        logged_message = await self.patches[patch_name].logs.listen()

        return Response(status=200, text=logged_message)

    @exceptions_to_http(SerializedError)
    async def save_current_patch(self, request: Request) -> Response:
        resource = await self.helper.get_resource_for_request(request)

        patch_info = await request.json()

        self.patches.get(patch_info["name"]).latest_metadata = patch_info
        return Response(
            status=200,
        )


class LogStreamer(TextIO):
    tmpfile_regex = re.compile(r"/tmp/tmp[a-zA-Z0-9]+/")

    def __init__(self):
        self.message_queue = asyncio.Queue()

    def write(self, msg: str):
        stripped_msg = self.tmpfile_regex.sub("", msg)
        self.message_queue.put_nowait(stripped_msg)

    def flush(self):
        pass

    async def listen(self) -> str:
        return await self.message_queue.get()


class PatchInProgress:
    def __init__(self, name: str, target_resource: Resource):
        self.name = name
        self.resource = target_resource
        self.build_tmp_dir = tempfile.TemporaryDirectory()

        self.logs = LogStreamer()
        self.currentLogger: Optional[logging.Logger] = None

        self.files: Dict[str, bytes] = {}

        self.patch_maker: Optional[PatchMaker] = None
        self.patch_bom: Optional[BOM] = None
        self.patch_bom_dir: Optional[str] = None
        self.target_linkable_bom_info: Optional[Tuple[BOM, PatchRegionConfig]] = None

        self.latest_metadata: Dict = {
            "name": self.name,
            "sourceInfos": [],
            "objectInfosValid": False,
            "objectInfos": [],
            "targetInfo": {"symbols": []},
            "targetInfoValid": False,
            "userInputs": {
                "symbols": [],
                "toolchain": None,
                "toolchainConfig": None,
            },
            "symbolRefMap": None,
        }

    def __del__(self):
        if self.build_tmp_dir:
            self.build_tmp_dir.cleanup()

    def add_file(self, name: str, body: bytes):
        self.files[name] = body

    def delete_file(self, name: str):
        del self.files[name]

    async def build_patch_bom(self, toolchain_type, toolchain_config):
        program_attributes = await self.resource.analyze(ProgramAttributes)

        self.currentLogger = logging.Logger("patchmaker logs", level=logging.DEBUG)
        self.currentLogger.addHandler(logging.StreamHandler(stream=self.logs))

        toolchain = self._try_and_log_errors(
            toolchain_type,
            program_attributes,
            toolchain_config,
            logger=self.currentLogger,
        )

        self.patch_maker = self._try_and_log_errors(
            PatchMaker,
            toolchain=toolchain,
            build_dir=self.build_tmp_dir.name,
            logger=self.currentLogger,
        )

        if self.patch_bom_dir:
            shutil.rmtree(self.patch_bom_dir)

        # Need to save this to make it possible to clear it later
        self.patch_bom_dir = os.path.join(self.build_tmp_dir.name, f"{self.name}_bom_files")

        with tempfile.TemporaryDirectory() as source_temp_dir:
            with tempfile.TemporaryDirectory() as header_temp_dir:
                source_list = []
                for filename, contents in self.files.items():
                    if filename.split(".")[-1] in ("c", "as", "S"):
                        # source file
                        path = os.path.join(source_temp_dir, filename)
                        with open(path, "wb") as f:
                            f.write(contents)
                        source_list.append(path)
                    else:
                        # header file (presumably)
                        path = os.path.join(header_temp_dir, filename)
                        with open(path, "wb") as f:
                            f.write(contents)

                self.patch_bom = self._try_and_log_errors(
                    self.patch_maker.make_bom,
                    name=self.name,
                    source_list=source_list,
                    object_list=[],
                    header_dirs=[header_temp_dir],
                )

        return self.patch_bom

    async def build_target_bom(self):
        target_program = await self.resource.view_as(Program)

        with tempfile.TemporaryDirectory() as stubs_sources_dir:
            self.target_linkable_bom_info = await target_program.make_linkable_bom(
                self.patch_maker,
                stubs_sources_dir,
                self.patch_bom.unresolved_symbols,
            )

        return self.target_linkable_bom_info

    async def inject_bom(self, patch_regions: PatchRegionConfig):
        exec_path = os.path.join(self.build_tmp_dir.name, "output_exec")

        fem = self._try_and_log_errors(
            self.patch_maker.make_fem,
            [(self.patch_bom, patch_regions), self.target_linkable_bom_info],
            exec_path,
        )

        await self.resource.run(
            SegmentInjectorModifier,
            SegmentInjectorModifierConfig.from_fem(fem),
        )

        # Refresh LinkableBinary with the LinkableSymbols used in this patch
        target_binary = await self.resource.view_as(LinkableBinary)
        program_attributes = await self.resource.analyze(ProgramAttributes)
        await target_binary.define_linkable_symbols_from_patch(
            fem.executable.symbols, program_attributes
        )

    def _try_and_log_errors(self, f, *args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ToolchainException as e:
            self.currentLogger.error(str(e))
            raise

        except PatchMakerException as e:
            self.currentLogger.error(str(e))
            raise

        except CalledProcessError as e:
            self.currentLogger.error(str(e))
            raise
