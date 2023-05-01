import logging
from dataclasses import dataclass
from types import ModuleType
from typing import Callable, Dict, Iterable, Union

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.core.filesystem import File
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.resource import Resource
from ofrak_type.error import AlreadyExistError

LOGGER = logging.getLogger(__name__)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Magic(ResourceAttributes):
    mime: str
    descriptor: str


class _LibmagicDependency(ComponentExternalTool):
    try:
        import magic

        magic_: ModuleType = magic
    except ImportError:
        magic_ = None

    def __init__(self):
        super().__init__(
            "libmagic",
            "https://linux.die.net/man/3/libmagic",
            install_check_arg="",
            apt_package="libmagic1",
            brew_package="libmagic",
        )

        try:
            import magic as _magic

            _LibmagicDependency._magic = _magic
        except ImportError:
            _LibmagicDependency._magic = None

    async def is_tool_installed(self) -> bool:
        return self.magic_ is not None


LIBMAGIC_DEP = _LibmagicDependency()


class MagicAnalyzer(Analyzer[None, Magic]):
    """
    Analyze a binary blob to extract its mimetype and magic description.
    """

    targets = (File, GenericBinary)
    outputs = (Magic,)
    external_dependencies = (LIBMAGIC_DEP,)

    async def analyze(self, resource: Resource, config=None) -> Magic:
        data = await resource.get_data()
        if LIBMAGIC_DEP.magic_ is None:
            raise ImportError("libmagic does not seem to be installed!")
        else:
            magic_mime = LIBMAGIC_DEP.magic_.from_buffer(data, mime=True)
            magic_description = LIBMAGIC_DEP.magic_.from_buffer(data)
            return Magic(magic_mime, magic_description)


class MagicMimeIdentifier(Identifier[None]):
    """
    Identify and add the appropriate tag for a given resource based on its mimetype.
    """

    id = b"MagicMimeIdentifier"
    targets = (File, GenericBinary)
    external_dependencies = (LIBMAGIC_DEP,)  # Indirect thru MagicAnalyzer, but worth tagging

    _tags_by_mime: Dict[str, ResourceTag] = dict()

    async def identify(self, resource: Resource, config=None):
        _magic = await resource.analyze(Magic)
        magic_mime = _magic.mime
        tag = MagicMimeIdentifier._tags_by_mime.get(magic_mime)
        if tag is not None:
            resource.add_tag(tag)

    @classmethod
    def register(cls, resource: ResourceTag, mime_types: Union[Iterable[str], str]):
        if isinstance(mime_types, str):
            mime_types = [mime_types]
        for mime_type in mime_types:
            if mime_type in cls._tags_by_mime:
                raise AlreadyExistError(f"Registering already-registered mime type: {mime_type}")
            cls._tags_by_mime[mime_type] = resource


class MagicDescriptionIdentifier(Identifier[None]):
    """
    Identify and add the appropriate tag for a given resource based on its mime description.
    """

    id = b"MagicDescriptionIdentifier"
    targets = (File, GenericBinary)
    external_dependencies = (LIBMAGIC_DEP,)  # Indirect thru MagicAnalyzer, but worth tagging

    _matchers: Dict[Callable, ResourceTag] = dict()

    async def identify(self, resource: Resource, config):
        _magic = await resource.analyze(Magic)
        magic_description = _magic.descriptor
        for matcher, resource_type in self._matchers.items():
            if matcher(magic_description):
                resource.add_tag(resource_type)

    @classmethod
    def register(cls, resource: ResourceTag, matcher: Callable):
        if matcher in cls._matchers:
            raise AlreadyExistError("Registering already-registered matcher")
        cls._matchers[matcher] = resource


MagicMimeIdentifier.register(GenericText, "text/plain")
MagicDescriptionIdentifier.register(
    GenericText, lambda desc: any([("ASCII text" in s) for s in desc.split(", ")])
)

MagicMimeIdentifier.register(GenericBinary, "application/octet-stream")
MagicDescriptionIdentifier.register(GenericBinary, lambda s: s == "data")
