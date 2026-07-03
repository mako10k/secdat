from __future__ import annotations

import ctypes
import ctypes.util
import os
from collections.abc import Sequence
from enum import IntEnum
from dataclasses import dataclass


PATH_MAX = 4096


class SecdatError(RuntimeError):
    pass


class KeySource(IntEnum):
    LOCKED = 0
    ENVIRONMENT = 1
    SESSION = 2
    ORPHANED = 3


class EffectiveSource(IntEnum):
    LOCKED = 0
    ENVIRONMENT = 1
    LOCAL_SESSION = 2
    INHERITED_SESSION = 3
    EXPLICIT_LOCK = 4
    BLOCKED = 5
    ORPHANED = 6


class RedactionFieldClass(IntEnum):
    SECRET_VALUE = 0
    SECRET_DERIVED_IDENTIFIER = 1
    NON_SECRET_METADATA = 2
    COMMAND_ARGV = 3
    PATH_DOMAIN_LABEL = 4
    PUBLIC_TEXT = 5


class _Options(ctypes.Structure):
    _fields_ = [
        ("dir", ctypes.c_char_p),
        ("domain", ctypes.c_char_p),
        ("store", ctypes.c_char_p),
    ]


class _StatusSummary(ctypes.Structure):
    _fields_ = [
        ("store_count", ctypes.c_size_t),
        ("visible_key_count", ctypes.c_size_t),
        ("wrapped_master_key_present", ctypes.c_int),
        ("key_source", ctypes.c_int),
        ("effective_source", ctypes.c_int),
        ("session_expires_at", ctypes.c_long),
        ("related_domain_root", ctypes.c_char * PATH_MAX),
    ]


class _ListFilters(ctypes.Structure):
    _fields_ = [
        ("include_pattern", ctypes.c_char_p),
        ("exclude_pattern", ctypes.c_char_p),
        ("safe", ctypes.c_int),
        ("unsafe_store", ctypes.c_int),
        ("bulk_gate", ctypes.c_int),
    ]


class _DomainFilters(ctypes.Structure):
    _fields_ = [
        ("pattern", ctypes.c_char_p),
        ("include_ancestors", ctypes.c_int),
        ("include_descendants", ctypes.c_int),
        ("include_inherited", ctypes.c_int),
    ]


class _ExecPlanOptions(ctypes.Structure):
    _fields_ = [
        ("inject_rules", ctypes.POINTER(ctypes.c_char_p)),
        ("inject_rule_count", ctypes.c_size_t),
        ("inject_files", ctypes.POINTER(ctypes.c_char_p)),
        ("inject_file_count", ctypes.c_size_t),
        ("bulk_gate", ctypes.c_int),
        ("command_resolution", ctypes.c_char_p),
        ("argv", ctypes.POINTER(ctypes.c_char_p)),
        ("argv_count", ctypes.c_size_t),
    ]


class _RedactionClassification(ctypes.Structure):
    _fields_ = [
        ("field_class", ctypes.c_int),
        ("class_name", ctypes.c_char_p),
        ("policy_name", ctypes.c_char_p),
        ("display_label", ctypes.c_char_p),
        ("value_allowed", ctypes.c_int),
    ]


class _KeyMetadata(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_char * PATH_MAX),
        ("store", ctypes.c_char * PATH_MAX),
        ("canonical_keyref", ctypes.c_char * (PATH_MAX * 2)),
        ("source_domain", ctypes.c_char * PATH_MAX),
        ("source_type", ctypes.c_char * 16),
        ("local", ctypes.c_int),
        ("inherited", ctypes.c_int),
        ("unsafe_store", ctypes.c_int),
        ("storage_mode", ctypes.c_char * 16),
        ("key_visibility", ctypes.c_char * 16),
        ("value_access", ctypes.c_char * 16),
        ("bulk_select", ctypes.c_char * 16),
    ]


class _KeyMetadataList(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(_KeyMetadata)),
        ("count", ctypes.c_size_t),
    ]


class _StoreMetadata(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * PATH_MAX),
    ]


class _StoreMetadataList(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(_StoreMetadata)),
        ("count", ctypes.c_size_t),
    ]


class _DomainMetadata(ctypes.Structure):
    _fields_ = [
        ("root", ctypes.c_char * PATH_MAX),
        ("unlocked", ctypes.c_int),
        ("key_source", ctypes.c_int),
        ("effective_source", ctypes.c_int),
        ("session_expires_at", ctypes.c_long),
        ("remaining_seconds", ctypes.c_long),
        ("related_domain_root", ctypes.c_char * PATH_MAX),
        ("store_count", ctypes.c_size_t),
        ("visible_key_count", ctypes.c_size_t),
        ("orphaned_domain", ctypes.c_int),
        ("wrapped_master_key_present", ctypes.c_int),
    ]


class _DomainMetadataList(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(_DomainMetadata)),
        ("count", ctypes.c_size_t),
    ]


class _RelationRefreshSuggestion(ctypes.Structure):
    _fields_ = [
        ("severity", ctypes.c_char_p),
        ("relation_id", ctypes.c_char_p),
        ("leaked_role", ctypes.c_char_p),
        ("refresh_role", ctypes.c_char_p),
        ("refresh_keyref", ctypes.c_char_p),
        ("reason", ctypes.c_char_p),
    ]


class _RelationRefreshSuggestionList(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(_RelationRefreshSuggestion)),
        ("count", ctypes.c_size_t),
    ]


@dataclass
class StatusSummary:
    store_count: int
    visible_key_count: int
    wrapped_master_key_present: bool
    key_source: KeySource
    effective_source: EffectiveSource
    session_expires_at: int
    related_domain_root: str


@dataclass
class KeyMetadata:
    key: str
    store: str
    canonical_keyref: str
    source_domain: str
    source_type: str
    local: bool
    inherited: bool
    unsafe_store: bool
    storage_mode: str
    key_visibility: str
    value_access: str
    bulk_select: str


@dataclass
class StoreMetadata:
    name: str


@dataclass
class DomainMetadata:
    root: str
    unlocked: bool
    key_source: KeySource
    effective_source: EffectiveSource
    session_expires_at: int
    remaining_seconds: int
    related_domain_root: str
    store_count: int
    visible_key_count: int
    orphaned_domain: bool
    wrapped_master_key_present: bool


@dataclass
class RedactionClassification:
    field_class: RedactionFieldClass
    class_name: str
    policy_name: str
    display_label: str
    value_allowed: bool


@dataclass
class RelationRefreshSuggestion:
    severity: str
    relation_id: str
    leaked_role: str
    refresh_role: str
    refresh_keyref: str
    reason: str


def _encode_optional(value: str | None) -> bytes | None:
    if value is None:
        return None
    return value.encode()


def _encode_string_array(values: Sequence[str] | None):
    encoded = [value.encode() for value in values or []]
    if not encoded:
        return None, encoded
    array_type = ctypes.c_char_p * len(encoded)
    return array_type(*encoded), encoded


def _decode_char_array(value) -> str:
    return bytes(value).split(b"\0", 1)[0].decode()


def _decode_c_string(value) -> str:
    if value is None:
        return ""
    return value.decode()


def _decode_required_c_string(value, label: str) -> str:
    if value is None:
        raise SecdatError(f"{label} returned null text")
    return value.decode()


def _decode_redaction_classification(classification: _RedactionClassification) -> RedactionClassification:
    return RedactionClassification(
        field_class=RedactionFieldClass(classification.field_class),
        class_name=_decode_required_c_string(classification.class_name, "redaction class_name"),
        policy_name=_decode_required_c_string(classification.policy_name, "redaction policy_name"),
        display_label=_decode_required_c_string(classification.display_label, "redaction display_label"),
        value_allowed=bool(classification.value_allowed),
    )


def _load_library(library_path: str | None) -> ctypes.CDLL:
    candidate = library_path or os.environ.get("SECDAT_SDK_LIBRARY") or ctypes.util.find_library("secdat") or "libsecdat.so"
    library = ctypes.CDLL(candidate)

    library.secdat_sdk_get.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_int),
    ]
    library.secdat_sdk_get.restype = ctypes.c_int

    library.secdat_sdk_set.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    library.secdat_sdk_set.restype = ctypes.c_int

    library.secdat_sdk_rm.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    library.secdat_sdk_rm.restype = ctypes.c_int

    library.secdat_sdk_mv.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    library.secdat_sdk_mv.restype = ctypes.c_int

    library.secdat_sdk_cp.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    library.secdat_sdk_cp.restype = ctypes.c_int

    library.secdat_sdk_mask.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
    ]
    library.secdat_sdk_mask.restype = ctypes.c_int

    library.secdat_sdk_unmask.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
    ]
    library.secdat_sdk_unmask.restype = ctypes.c_int

    library.secdat_sdk_unlock.argtypes = [ctypes.POINTER(_Options)]
    library.secdat_sdk_unlock.restype = ctypes.c_int

    library.secdat_sdk_lock.argtypes = [ctypes.POINTER(_Options)]
    library.secdat_sdk_lock.restype = ctypes.c_int

    library.secdat_sdk_exists.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    library.secdat_sdk_exists.restype = ctypes.c_int

    library.secdat_sdk_collect_status.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.POINTER(_StatusSummary),
    ]
    library.secdat_sdk_collect_status.restype = ctypes.c_int

    library.secdat_sdk_list_keys.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.POINTER(_ListFilters),
        ctypes.POINTER(_KeyMetadataList),
    ]
    library.secdat_sdk_list_keys.restype = ctypes.c_int

    library.secdat_sdk_list_stores.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.POINTER(_StoreMetadataList),
    ]
    library.secdat_sdk_list_stores.restype = ctypes.c_int

    library.secdat_sdk_list_domains.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.POINTER(_DomainFilters),
        ctypes.POINTER(_DomainMetadataList),
    ]
    library.secdat_sdk_list_domains.restype = ctypes.c_int

    library.secdat_sdk_exec_plan_json.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.POINTER(_ExecPlanOptions),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.secdat_sdk_exec_plan_json.restype = ctypes.c_int

    library.secdat_sdk_redaction_class_name.argtypes = [ctypes.c_int]
    library.secdat_sdk_redaction_class_name.restype = ctypes.c_char_p

    library.secdat_sdk_redaction_policy_name.argtypes = [ctypes.c_int]
    library.secdat_sdk_redaction_policy_name.restype = ctypes.c_char_p

    library.secdat_sdk_redaction_display_label.argtypes = [ctypes.c_int]
    library.secdat_sdk_redaction_display_label.restype = ctypes.c_char_p

    library.secdat_sdk_redaction_value_allowed.argtypes = [ctypes.c_int]
    library.secdat_sdk_redaction_value_allowed.restype = ctypes.c_int

    library.secdat_sdk_describe_redaction_class.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_RedactionClassification),
    ]
    library.secdat_sdk_describe_redaction_class.restype = ctypes.c_int

    library.secdat_sdk_classify_exec_json_field.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(_RedactionClassification),
    ]
    library.secdat_sdk_classify_exec_json_field.restype = ctypes.c_int

    library.secdat_sdk_relation_suggest_refresh.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_char_p,
        ctypes.POINTER(_RelationRefreshSuggestionList),
    ]
    library.secdat_sdk_relation_suggest_refresh.restype = ctypes.c_int

    library.secdat_sdk_wait_unlock.argtypes = [
        ctypes.POINTER(_Options),
        ctypes.c_long,
    ]
    library.secdat_sdk_wait_unlock.restype = ctypes.c_int

    library.secdat_sdk_free.argtypes = [ctypes.c_void_p]
    library.secdat_sdk_free.restype = None
    return library


class Secdat:
    def __init__(self, library_path: str | None = None):
        self._lib = _load_library(library_path)

    def _options(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> _Options:
        return _Options(_encode_optional(dir), _encode_optional(domain), _encode_optional(store))

    def get(self, keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> tuple[bytes, bool]:
        options = self._options(dir=dir, domain=domain, store=store)
        value = ctypes.POINTER(ctypes.c_ubyte)()
        value_length = ctypes.c_size_t()
        unsafe_store = ctypes.c_int()
        result = self._lib.secdat_sdk_get(ctypes.byref(options), keyref.encode(), ctypes.byref(value), ctypes.byref(value_length), ctypes.byref(unsafe_store))
        if result != 0:
            raise SecdatError(f"secdat_sdk_get failed with status {result}; see stderr for details")

        try:
            payload = ctypes.string_at(value, value_length.value)
        finally:
            self._lib.secdat_sdk_free(ctypes.cast(value, ctypes.c_void_p))
        return payload, bool(unsafe_store.value)

    def set(self, keyref: str, value: bytes | str, *, dir: str | None = None, domain: str | None = None, store: str | None = None, unsafe_store: bool = False) -> None:
        payload = value.encode() if isinstance(value, str) else value
        options = self._options(dir=dir, domain=domain, store=store)
        buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload) if payload else None
        result = self._lib.secdat_sdk_set(ctypes.byref(options), keyref.encode(), buffer, len(payload), int(unsafe_store))
        if result != 0:
            raise SecdatError(f"secdat_sdk_set failed with status {result}; see stderr for details")

    def rm(self, keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None, ignore_missing: bool = False) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_rm(ctypes.byref(options), keyref.encode(), int(ignore_missing))
        if result != 0:
            raise SecdatError(f"secdat_sdk_rm failed with status {result}; see stderr for details")

    def mv(self, source_keyref: str, destination_keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_mv(ctypes.byref(options), source_keyref.encode(), destination_keyref.encode())
        if result != 0:
            raise SecdatError(f"secdat_sdk_mv failed with status {result}; see stderr for details")

    def cp(self, source_keyref: str, destination_keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_cp(ctypes.byref(options), source_keyref.encode(), destination_keyref.encode())
        if result != 0:
            raise SecdatError(f"secdat_sdk_cp failed with status {result}; see stderr for details")

    def mask(self, keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_mask(ctypes.byref(options), keyref.encode())
        if result != 0:
            raise SecdatError(f"secdat_sdk_mask failed with status {result}; see stderr for details")

    def unmask(self, keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_unmask(ctypes.byref(options), keyref.encode())
        if result != 0:
            raise SecdatError(f"secdat_sdk_unmask failed with status {result}; see stderr for details")

    def unlock(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_unlock(ctypes.byref(options))
        if result != 0:
            raise SecdatError(f"secdat_sdk_unlock failed with status {result}; see stderr for details")

    def lock(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_lock(ctypes.byref(options))
        if result != 0:
            raise SecdatError(f"secdat_sdk_lock failed with status {result}; see stderr for details")

    def exists(self, keyref: str, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> bool:
        options = self._options(dir=dir, domain=domain, store=store)
        exists = ctypes.c_int()
        result = self._lib.secdat_sdk_exists(ctypes.byref(options), keyref.encode(), ctypes.byref(exists))
        if result != 0:
            raise SecdatError(f"secdat_sdk_exists failed with status {result}; see stderr for details")
        return bool(exists.value)

    def collect_status(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> StatusSummary:
        options = self._options(dir=dir, domain=domain, store=store)
        summary = _StatusSummary()
        result = self._lib.secdat_sdk_collect_status(ctypes.byref(options), ctypes.byref(summary))
        if result != 0:
            raise SecdatError(f"secdat_sdk_collect_status failed with status {result}; see stderr for details")
        return StatusSummary(
            store_count=int(summary.store_count),
            visible_key_count=int(summary.visible_key_count),
            wrapped_master_key_present=bool(summary.wrapped_master_key_present),
            key_source=KeySource(summary.key_source),
            effective_source=EffectiveSource(summary.effective_source),
            session_expires_at=int(summary.session_expires_at),
            related_domain_root=_decode_char_array(summary.related_domain_root),
        )

    def list_keys(
        self,
        *,
        dir: str | None = None,
        domain: str | None = None,
        store: str | None = None,
        include_pattern: str | None = None,
        exclude_pattern: str | None = None,
        safe: bool = False,
        unsafe_store: bool = False,
        bulk_gate: bool = False,
    ) -> list[KeyMetadata]:
        options = self._options(dir=dir, domain=domain, store=store)
        filters = _ListFilters(
            _encode_optional(include_pattern),
            _encode_optional(exclude_pattern),
            int(safe),
            int(unsafe_store),
            int(bulk_gate),
        )
        result_list = _KeyMetadataList()
        result = self._lib.secdat_sdk_list_keys(ctypes.byref(options), ctypes.byref(filters), ctypes.byref(result_list))
        if result != 0:
            raise SecdatError(f"secdat_sdk_list_keys failed with status {result}; see stderr for details")
        try:
            if result_list.count == 0:
                return []
            return [
                KeyMetadata(
                    key=_decode_char_array(item.key),
                    store=_decode_char_array(item.store),
                    canonical_keyref=_decode_char_array(item.canonical_keyref),
                    source_domain=_decode_char_array(item.source_domain),
                    source_type=_decode_char_array(item.source_type),
                    local=bool(item.local),
                    inherited=bool(item.inherited),
                    unsafe_store=bool(item.unsafe_store),
                    storage_mode=_decode_char_array(item.storage_mode),
                    key_visibility=_decode_char_array(item.key_visibility),
                    value_access=_decode_char_array(item.value_access),
                    bulk_select=_decode_char_array(item.bulk_select),
                )
                for item in result_list.items[: result_list.count]
            ]
        finally:
            self._lib.secdat_sdk_free(ctypes.cast(result_list.items, ctypes.c_void_p))

    def list_stores(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None) -> list[StoreMetadata]:
        options = self._options(dir=dir, domain=domain, store=store)
        result_list = _StoreMetadataList()
        result = self._lib.secdat_sdk_list_stores(ctypes.byref(options), ctypes.byref(result_list))
        if result != 0:
            raise SecdatError(f"secdat_sdk_list_stores failed with status {result}; see stderr for details")
        try:
            if result_list.count == 0:
                return []
            return [StoreMetadata(name=_decode_char_array(item.name)) for item in result_list.items[: result_list.count]]
        finally:
            self._lib.secdat_sdk_free(ctypes.cast(result_list.items, ctypes.c_void_p))

    def list_domains(
        self,
        *,
        dir: str | None = None,
        domain: str | None = None,
        store: str | None = None,
        pattern: str | None = None,
        include_ancestors: bool = False,
        include_descendants: bool = False,
        include_inherited: bool = False,
    ) -> list[DomainMetadata]:
        options = self._options(dir=dir, domain=domain, store=store)
        filters = _DomainFilters(
            _encode_optional(pattern),
            int(include_ancestors),
            int(include_descendants),
            int(include_inherited),
        )
        result_list = _DomainMetadataList()
        result = self._lib.secdat_sdk_list_domains(ctypes.byref(options), ctypes.byref(filters), ctypes.byref(result_list))
        if result != 0:
            raise SecdatError(f"secdat_sdk_list_domains failed with status {result}; see stderr for details")
        try:
            if result_list.count == 0:
                return []
            return [
                DomainMetadata(
                    root=_decode_char_array(item.root),
                    unlocked=bool(item.unlocked),
                    key_source=KeySource(item.key_source),
                    effective_source=EffectiveSource(item.effective_source),
                    session_expires_at=int(item.session_expires_at),
                    remaining_seconds=int(item.remaining_seconds),
                    related_domain_root=_decode_char_array(item.related_domain_root),
                    store_count=int(item.store_count),
                    visible_key_count=int(item.visible_key_count),
                    orphaned_domain=bool(item.orphaned_domain),
                    wrapped_master_key_present=bool(item.wrapped_master_key_present),
                )
                for item in result_list.items[: result_list.count]
            ]
        finally:
            self._lib.secdat_sdk_free(ctypes.cast(result_list.items, ctypes.c_void_p))

    def exec_plan_json(
        self,
        argv: Sequence[str],
        *,
        dir: str | None = None,
        domain: str | None = None,
        store: str | None = None,
        inject_rules: Sequence[str] | None = None,
        inject_files: Sequence[str] | None = None,
        bulk_gate: bool = False,
        command_resolution: str | None = None,
    ) -> str:
        options = self._options(dir=dir, domain=domain, store=store)
        inject_rule_array, _inject_rule_values = _encode_string_array(inject_rules)
        inject_file_array, _inject_file_values = _encode_string_array(inject_files)
        argv_array, _argv_values = _encode_string_array(argv)
        plan_options = _ExecPlanOptions(
            inject_rule_array,
            len(inject_rules or []),
            inject_file_array,
            len(inject_files or []),
            int(bulk_gate),
            _encode_optional(command_resolution),
            argv_array,
            len(argv),
        )
        json_pointer = ctypes.c_void_p()
        result = self._lib.secdat_sdk_exec_plan_json(ctypes.byref(options), ctypes.byref(plan_options), ctypes.byref(json_pointer))
        try:
            if not json_pointer.value:
                raise SecdatError(f"secdat_sdk_exec_plan_json failed with status {result}; see stderr for details")
            return ctypes.string_at(json_pointer.value).decode()
        finally:
            if json_pointer.value:
                self._lib.secdat_sdk_free(json_pointer)

    def redaction_class_name(self, field_class: RedactionFieldClass) -> str:
        value = self._lib.secdat_sdk_redaction_class_name(int(field_class))
        return _decode_required_c_string(value, "secdat_sdk_redaction_class_name")

    def redaction_policy_name(self, field_class: RedactionFieldClass) -> str:
        value = self._lib.secdat_sdk_redaction_policy_name(int(field_class))
        return _decode_required_c_string(value, "secdat_sdk_redaction_policy_name")

    def redaction_display_label(self, field_class: RedactionFieldClass) -> str:
        value = self._lib.secdat_sdk_redaction_display_label(int(field_class))
        return _decode_required_c_string(value, "secdat_sdk_redaction_display_label")

    def redaction_value_allowed(self, field_class: RedactionFieldClass) -> bool:
        return bool(self._lib.secdat_sdk_redaction_value_allowed(int(field_class)))

    def describe_redaction_class(self, field_class: RedactionFieldClass) -> RedactionClassification:
        classification = _RedactionClassification()
        result = self._lib.secdat_sdk_describe_redaction_class(int(field_class), ctypes.byref(classification))
        if result != 0:
            raise SecdatError(f"secdat_sdk_describe_redaction_class failed with status {result}; see stderr for details")
        return _decode_redaction_classification(classification)

    def classify_exec_json_field(self, field_path: str) -> RedactionClassification:
        classification = _RedactionClassification()
        result = self._lib.secdat_sdk_classify_exec_json_field(field_path.encode(), ctypes.byref(classification))
        if result != 0:
            raise SecdatError(f"secdat_sdk_classify_exec_json_field failed with status {result}; see stderr for details")
        return _decode_redaction_classification(classification)

    def relation_suggest_refresh(
        self,
        keyref: str,
        *,
        dir: str | None = None,
        domain: str | None = None,
        store: str | None = None,
    ) -> list[RelationRefreshSuggestion]:
        options = self._options(dir=dir, domain=domain, store=store)
        result_list = _RelationRefreshSuggestionList()
        result = self._lib.secdat_sdk_relation_suggest_refresh(ctypes.byref(options), keyref.encode(), ctypes.byref(result_list))
        if result != 0:
            raise SecdatError(f"secdat_sdk_relation_suggest_refresh failed with status {result}; see stderr for details")
        try:
            if result_list.count == 0:
                return []
            return [
                RelationRefreshSuggestion(
                    severity=_decode_c_string(item.severity),
                    relation_id=_decode_c_string(item.relation_id),
                    leaked_role=_decode_c_string(item.leaked_role),
                    refresh_role=_decode_c_string(item.refresh_role),
                    refresh_keyref=_decode_c_string(item.refresh_keyref),
                    reason=_decode_c_string(item.reason),
                )
                for item in result_list.items[: result_list.count]
            ]
        finally:
            self._lib.secdat_sdk_free(ctypes.cast(result_list.items, ctypes.c_void_p))

    def wait_unlock(self, *, dir: str | None = None, domain: str | None = None, store: str | None = None, timeout_seconds: int = 0) -> None:
        options = self._options(dir=dir, domain=domain, store=store)
        result = self._lib.secdat_sdk_wait_unlock(ctypes.byref(options), timeout_seconds)
        if result != 0:
            raise SecdatError(f"secdat_sdk_wait_unlock failed with status {result}; see stderr for details")
