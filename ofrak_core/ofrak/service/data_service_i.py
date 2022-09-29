from abc import ABCMeta, abstractmethod
from typing import List, Iterable, Optional

from ofrak.model.data_model import DataModel, DataPatch, DataPatchesResult, DataMove
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak_type.range import Range


class DataServiceInterface(AbstractOfrakService, metaclass=ABCMeta):
    @abstractmethod
    async def create(self, data_id: bytes, data: bytes, alignment: int = 0) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def create_mapped(
        self,
        data_id: bytes,
        root_id: bytes,
        range: Range,
        alignment: int = 0,
        # after_data_id: Optional[bytes] = None,
        # before_data_id: Optional[bytes] = None,
    ) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def get_by_id(self, data_id: bytes) -> DataModel:
        raise NotImplementedError()

    @abstractmethod
    async def get_by_ids(self, data_ids: Iterable[bytes]) -> Iterable[DataModel]:
        raise NotImplementedError()

    # @abstractmethod
    # async def get_data_length(self, data_id: bytes) -> int:
    #     raise NotImplementedError()

    # unused = unneeded?
    # @abstractmethod
    async def get_unmapped_range(self, data_id: bytes, offset: int) -> Range:
        raise NotImplementedError()

    # unused = unneeded?
    # @abstractmethod
    async def get_unmapped_ranges(
        self, data_id: bytes, sort_by_size: bool = False, bounds: Optional[Range] = None
    ) -> Iterable[Range]:
        raise NotImplementedError()

    # unused = UNNEEDED
    # @abstractmethod
    # async def get_index_within_parent(self, data_id: bytes) -> int:
    #     raise NotImplementedError()

    # @abstractmethod
    # async def get_range_within_parent(self, data_id: bytes) -> Range:
    #     raise NotImplementedError()
    #
    # @abstractmethod
    # async def get_range_within_ancestor(self, data_id: bytes, ancestor_id: bytes) -> Range:
    #     raise NotImplementedError()

    @abstractmethod
    async def get_data_range_within_root(self, data_id: bytes) -> Range:
        raise NotImplementedError()

    @abstractmethod
    async def get_range_within_other(self, data_id: bytes, within_data_id: bytes) -> Range:
        raise NotImplementedError()

    @abstractmethod
    async def get_data(self, data_id: bytes, data_range: Range = None) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    async def set_alignment(self, data_id: bytes, alignment: int):
        raise NotImplementedError()

    # Overlaps might not always be allowed, if all mapped nodes are siblings
    # Or, the meaning of overlap may change, so instead we have to be careful of node's boundaries being inside another node
    # @abstractmethod
    async def set_overlaps_enabled(self, data_id: bytes, enable_overlaps: bool):
        raise NotImplementedError()

    @abstractmethod
    async def apply_patches(
        self,
        patches: Optional[List[DataPatch]] = None,
        moves: Optional[List[DataMove]] = None,
    ) -> List[DataPatchesResult]:
        raise NotImplementedError()

    @abstractmethod
    async def delete_node(self, data_id: bytes) -> None:
        """
        Delete a node and re-arrange its children to the deleted node's parent.

        :param data_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def delete_models(self, data_ids: Iterable[bytes]) -> None:
        """
        Delete one or more data models. If a root model is deleted, all models mapped into that
        root are also deleted.

        :param data_ids:
        :return:
        """
        raise NotImplementedError()

    # KILL
    # @abstractmethod
    async def merge_siblings(self, new_data_id: bytes, merging_data_ids: Iterable[bytes]) -> None:
        """
        Merge the specified siblings into a new node, which has the same parent as the siblings
        and takes the children of the siblings.

        :param new_data_id:
        :param merging_data_ids:
        :return:
        """
        raise NotImplementedError()

    # KILL
    # @abstractmethod
    async def gather_siblings(
        self, new_data_id: bytes, gathering_data_ids: Iterable[bytes]
    ) -> None:
        """
        Create a new common parent for the specified `data_id`s. This common parent will be a
        child of the gathered nodes's existing common parent.

        :param new_data_id:
        :param gathering_data_ids:
        :return:
        """
        raise NotImplementedError()

    # KILL
    # @abstractmethod
    async def delete_tree(self, data_id: bytes) -> None:
        """
        Delete a data node and all of its children.

        :param data_id:
        :return:
        """
        raise NotImplementedError()

    # YUCKY
    # @abstractmethod
    async def create_savepoint(self) -> str:
        # List of data changes (including original)
        # Dict[SavepointID, index in that list)
        raise NotImplementedError()

    # SO YUCKY
    # @abstractmethod
    async def get_patches_between_savepoints(
        self,
        start_savepoint: str,
        end_savepoint: str = "",
    ) -> List[List[DataPatch]]:
        raise NotImplementedError()
