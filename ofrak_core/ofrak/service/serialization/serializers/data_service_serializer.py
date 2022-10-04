from typing import Dict, Any, Set

from sortedcontainers import SortedList

from ofrak.model.data_model import DataModel
from ofrak.service.new_data_service import NewDataService, _DataRoot, _Waypoint
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class DataServiceSerializer(SerializerInterface):
    """
    Serialize and deserialize `DataService` into `PJSONType`.

    The `DataService` has some internal data structures which require custom
    serialization/deserialization, specifically the _DataRoot and _Waypoint. This is done with
    methods of this class, and avoids serializing redundant information.
    """

    targets = (NewDataService,)

    def obj_to_pjson(self, obj: NewDataService, _type_hint: Any) -> Dict[str, PJSONType]:
        data_service_pjson = {
            "_model_store": self._service.to_pjson(obj._model_store, Dict[bytes, DataModel]),
            "_roots": [self._data_root_to_pjson(data_root) for data_root in obj._roots],
        }

        return data_service_pjson

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> NewDataService:
        _model_store = self._service.from_pjson(pjson_obj["_model_store"], Dict[bytes, DataModel])
        _roots = dict()
        for root_pjson in pjson_obj["_roots"]:
            root_obj = self._data_root_from_pjson(root_pjson, _model_store)
            _roots[root_obj.model.id] = root_obj

        data_service: NewDataService = NewDataService.__new__(NewDataService)
        data_service._model_store = _model_store
        data_service._roots = _roots

        return data_service

    def _data_root_to_pjson(self, data_root: _DataRoot) -> PJSONType:
        return {
            "root_id": self._service.to_pjson(data_root.model.id, bytes),
            "data": self._service.to_pjson(data_root.data, bytes),
            "waypoints": [
                self._waypoint_from_pjson(data_root._waypoints[wp_offset])
                for wp_offset in data_root._waypoint_offsets
            ],
            "children": self._service.to_pjson(data_root._children.keys(), Set[bytes]),
        }

    def _data_root_from_pjson(
        self, data_root_pjson: PJSONType, models: Dict[bytes, DataModel]
    ) -> _DataRoot:
        root_id = self._service.from_pjson(data_root_pjson["root_id"], bytes)
        data = self._service.from_pjson(data_root_pjson["data"], bytes)
        raw_waypoints = [
            self._waypoint_from_pjson(waypoint_pjson)
            for waypoint_pjson in data_root_pjson["waypoints"]
        ]
        raw_children = self._service.from_pjson(data_root_pjson["children"], Set[bytes])

        root_model = models[root_id]

        waypoints = {waypoint.offset: waypoint for waypoint in raw_waypoints}
        waypoint_offsets = SortedList(waypoints.keys())

        children = {child_id: models[child_id] for child_id in raw_children}

        data_root: _DataRoot = _DataRoot.__new__(_DataRoot)
        data_root.model = root_model
        data_root.data = data
        data_root._waypoints = waypoints
        data_root._waypoint_offsets = waypoint_offsets
        data_root._chilren = children

        return data_root

    def _waypoint_to_pjson(self, waypoint: _Waypoint) -> PJSONType:
        return (
            waypoint.offset,
            self._service.to_pjson(waypoint.models_starting, Set[bytes]),
            self._service.to_pjson(waypoint.models_ending, Set[bytes]),
        )

    def _waypoint_from_pjson(self, waypoint_pjson: PJSONType) -> _Waypoint:
        offset, models_starting_pjson, models_ending_pjson = waypoint_pjson
        models_starting = self._service.from_pjson(models_starting_pjson, Set[bytes])
        models_ending = self._service.from_pjson(models_ending_pjson, Set[bytes])
        return _Waypoint(offset, models_starting, models_ending)
