import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass

from ofrak import Resource, Packer, Unpacker
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core import (
    File,
    Folder,
    FilesystemRoot,
    SpecialFileType,
    format_called_process_error,
    MagicMimeIdentifier,
    MagicDescriptionIdentifier,
    GenericBinary,
)
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class ZipArchive(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a zip archive.
    """


class ZipUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a zip archive.
    """

    targets = (ZipArchive,)
    children = (File, Folder, SpecialFileType)

    async def unpack(self, resource: Resource, config=None):
        zip_view = await resource.view_as(ZipArchive)
        with tempfile.NamedTemporaryFile(suffix=".zip") as temp_archive:
            temp_archive.write(await resource.get_data())
            temp_archive.flush()
            with tempfile.TemporaryDirectory() as temp_dir:
                command = ["unzip", temp_archive.name, "-d", temp_dir]
                try:
                    subprocess.run(command, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    raise UnpackerError(format_called_process_error(e))
                cwd = os.getcwd()
                os.chdir(temp_dir)
                await zip_view.initialize_from_disk(temp_dir)
                os.chdir(cwd)


class ZipPacker(Packer[None]):
    """
    Pack files into a compressed zip archive.
    """

    targets = (ZipArchive,)

    async def pack(self, resource: Resource, config=None):
        zip_view: ZipArchive = await resource.view_as(ZipArchive)
        flush_dir = await zip_view.flush_to_disk()
        temp_archive = f"{flush_dir}.zip"
        cwd = os.getcwd()
        os.chdir(flush_dir)
        command = ["zip", "-r", temp_archive, "."]
        try:
            subprocess.run(command, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            raise PackerError(format_called_process_error(e))
        os.chdir(cwd)
        with open(temp_archive, "rb") as fh:
            resource.queue_patch(Range(0, await zip_view.resource.get_data_length()), fh.read())


MagicMimeIdentifier.register(ZipArchive, "application/zip")
MagicDescriptionIdentifier.register(
    ZipArchive, lambda desc: any([("Zip archive data" in s) for s in desc.split(", ")])
)
