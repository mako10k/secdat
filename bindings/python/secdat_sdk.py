from __future__ import annotations

import ctypes
import ctypes.util
import os
from dataclasses import dataclass


PATH_MAX = 4096


class SecdatError(RuntimeError):
    pass


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


@dataclass
class StatusSummary:
    store_count: int
    visible_key_count: int
    wrapped_master_key_present: bool
    key_source: int
    effective_source: int
    session_expires_at: int
    related_domain_root: str


def _encode_optional(value: str | None) -> bytes | None:
    if value is None:
        return None
    return value.encode()


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
        related_domain_root = bytes(summary.related_domain_root).split(b"\0", 1)[0].decode()
        return StatusSummary(
            store_count=int(summary.store_count),
            visible_key_count=int(summary.visible_key_count),
            wrapped_master_key_present=bool(summary.wrapped_master_key_present),
            key_source=int(summary.key_source),
            effective_source=int(summary.effective_source),
            session_expires_at=int(summary.session_expires_at),
            related_domain_root=related_domain_root,
        )