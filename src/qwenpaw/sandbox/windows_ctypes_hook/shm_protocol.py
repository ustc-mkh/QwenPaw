# -*- coding: utf-8 -*-
"""Shared memory protocol for communication with the parent process.

Implements the same binary layout as sandbox_hook.h:
  - 64-byte header (SANDBOX_POLICY_HEADER)
  - policy_length bytes of UTF-8 JSON
  - violation_log_size bytes ring buffer

Used by sandbox_runner.py to:
  1. Read the policy JSON written by the parent
  2. Write violation entries when file access is denied
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import struct
import sys

assert sys.platform == "win32", "This module is Windows-only"

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Constants (must match sandbox_hook.h)
# ═══════════════════════════════════════════════════════════════════════════════

SANDBOX_MAGIC = 0x51574E50  # "QWNP" little-endian
SANDBOX_VERSION = 1
SANDBOX_HEADER_SIZE = 64  # bytes
SANDBOX_SHM_PREFIX = "Local\\QwenPaw_HookPolicy_"
SANDBOX_VIOLATION_LOG_SIZE = 64 * 1024

# Header field offsets (packed, no padding)
_OFF_MAGIC = 0
_OFF_VERSION = 4
_OFF_POLICY_LENGTH = 8
_OFF_FLAGS = 12
_OFF_VIOLATION_LOG_OFFSET = 16
_OFF_VIOLATION_LOG_SIZE = 20
_OFF_VIOLATION_COUNT = 24
_OFF_VIOLATION_WRITE_POS = 28

# VIOLATION_ENTRY size (fixed header, excluding variable-length path)
_VIOLATION_ENTRY_HDR_SIZE = 20  # total_size(4) + timestamp(4) + pid(4) + tid(4) + path_length(2) + access_type(2)

# Windows API constants
FILE_MAP_ALL_ACCESS = 0x001F

# ═══════════════════════════════════════════════════════════════════════════════
# Kernel32 bindings
# ═══════════════════════════════════════════════════════════════════════════════

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.OpenFileMappingW.restype = ctypes.wintypes.HANDLE
_kernel32.OpenFileMappingW.argtypes = [
    ctypes.wintypes.DWORD,  # dwDesiredAccess
    ctypes.wintypes.BOOL,  # bInheritHandle
    ctypes.c_wchar_p,  # lpName
]

_kernel32.MapViewOfFile.restype = ctypes.c_void_p
_kernel32.MapViewOfFile.argtypes = [
    ctypes.wintypes.HANDLE,  # hFileMappingObject
    ctypes.wintypes.DWORD,  # dwDesiredAccess
    ctypes.wintypes.DWORD,  # dwFileOffsetHigh
    ctypes.wintypes.DWORD,  # dwFileOffsetLow
    ctypes.c_size_t,  # dwNumberOfBytesToMap
]

_kernel32.UnmapViewOfFile.restype = ctypes.wintypes.BOOL
_kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]

_kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
_kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

_kernel32.GetTickCount.restype = ctypes.wintypes.DWORD
_kernel32.GetTickCount.argtypes = []

_kernel32.GetCurrentThreadId.restype = ctypes.wintypes.DWORD
_kernel32.GetCurrentThreadId.argtypes = []


# ═══════════════════════════════════════════════════════════════════════════════
# SharedMemory class
# ═══════════════════════════════════════════════════════════════════════════════


class SharedMemoryReader:
    """Reads policy and writes violations to the parent's shared memory."""

    def __init__(self, session_id: str):
        self._session_id = session_id
        self._handle: int = 0
        self._view: int = 0
        self._violation_log_offset: int = 0
        self._violation_log_size: int = 0

    def open(self) -> None:
        """Open the named shared memory section created by the parent."""
        shm_name = f"{SANDBOX_SHM_PREFIX}{self._session_id}"

        self._handle = _kernel32.OpenFileMappingW(
            FILE_MAP_ALL_ACCESS,
            False,
            shm_name,
        )
        if not self._handle:
            err = ctypes.get_last_error()
            raise OSError(
                f"OpenFileMappingW({shm_name!r}) failed: error {err}"
            )

        self._view = _kernel32.MapViewOfFile(
            self._handle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            0,
        )
        if not self._view:
            err = ctypes.get_last_error()
            _kernel32.CloseHandle(self._handle)
            self._handle = 0
            raise OSError(f"MapViewOfFile failed: error {err}")

        # Validate header
        header = self._read_bytes(0, SANDBOX_HEADER_SIZE)
        magic, version = struct.unpack_from("<II", header, 0)
        if magic != SANDBOX_MAGIC:
            raise ValueError(
                f"Shared memory magic mismatch: expected 0x{SANDBOX_MAGIC:08X}, "
                f"got 0x{magic:08X}"
            )
        if version != SANDBOX_VERSION:
            raise ValueError(
                f"Shared memory version mismatch: expected {SANDBOX_VERSION}, "
                f"got {version}"
            )

        self._violation_log_offset = struct.unpack_from(
            "<I", header, _OFF_VIOLATION_LOG_OFFSET
        )[0]
        self._violation_log_size = struct.unpack_from(
            "<I", header, _OFF_VIOLATION_LOG_SIZE
        )[0]

        logger.debug(
            "Opened shared memory: session=%s, log_offset=%d, log_size=%d",
            self._session_id,
            self._violation_log_offset,
            self._violation_log_size,
        )

    def read_policy_json(self) -> str:
        """Read the UTF-8 JSON policy from shared memory."""
        header = self._read_bytes(0, SANDBOX_HEADER_SIZE)
        policy_len = struct.unpack_from("<I", header, _OFF_POLICY_LENGTH)[0]
        if policy_len == 0:
            return "{}"
        policy_bytes = self._read_bytes(SANDBOX_HEADER_SIZE, policy_len)
        return policy_bytes.decode("utf-8")

    def log_violation(self, path: str, access_type: int) -> None:
        """Write a violation entry to the ring buffer.

        Args:
            path: The normalized file path that was denied.
            access_type: VIOLATION_* flag indicating the access type.
        """
        if not self._view:
            return

        path_utf16 = path.encode("utf-16-le")
        path_wchar_count = len(path)
        entry_size = _VIOLATION_ENTRY_HDR_SIZE + len(path_utf16)

        if entry_size > self._violation_log_size:
            return

        # Read current write position
        wp_bytes = self._read_bytes(_OFF_VIOLATION_WRITE_POS, 4)
        write_pos = struct.unpack("<I", wp_bytes)[0] % self._violation_log_size

        # Wrap if insufficient space at end of buffer
        if write_pos + entry_size > self._violation_log_size:
            write_pos = 0

        # Build violation entry
        entry = struct.pack(
            "<IIIIHH",
            entry_size,  # total_size
            _kernel32.GetTickCount(),  # timestamp
            os.getpid(),  # pid
            _kernel32.GetCurrentThreadId(),  # tid
            path_wchar_count,  # path_length (in WCHARs)
            access_type,  # access_type
        )

        # Write entry to ring buffer
        log_base = self._violation_log_offset
        self._write_bytes(log_base + write_pos, entry + path_utf16)

        # Update write position
        new_wp = write_pos + entry_size
        self._write_bytes(_OFF_VIOLATION_WRITE_POS, struct.pack("<I", new_wp))

        # Increment violation count
        # Safe: only this process writes; parent reads after we exit.
        count_bytes = self._read_bytes(_OFF_VIOLATION_COUNT, 4)
        count = struct.unpack("<I", count_bytes)[0] + 1
        self._write_bytes(_OFF_VIOLATION_COUNT, struct.pack("<I", count))

    def close(self) -> None:
        """Unmap and close the shared memory."""
        if self._view:
            _kernel32.UnmapViewOfFile(ctypes.c_void_p(self._view))
            self._view = 0
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = 0

    def _read_bytes(self, offset: int, length: int) -> bytes:
        """Read raw bytes from the shared memory view."""
        buf = (ctypes.c_byte * length)()
        ctypes.memmove(buf, ctypes.c_void_p(self._view + offset), length)
        return bytes(buf)

    def _write_bytes(self, offset: int, data: bytes) -> None:
        """Write raw bytes to the shared memory view."""
        ctypes.memmove(
            ctypes.c_void_p(self._view + offset),
            data,
            len(data),
        )

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
