# -*- coding: utf-8 -*-
"""NT API ctypes type definitions for Windows x64.

Defines the structures and function signatures needed to hook
NtCreateFile, NtOpenFile, NtDeleteFile, and CreateProcessW/A.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys

# Only usable on Windows
assert sys.platform == "win32", "This module is Windows-only"

# ═══════════════════════════════════════════════════════════════════════════════
# Basic NT types
# ═══════════════════════════════════════════════════════════════════════════════

NTSTATUS = ctypes.c_long
PVOID = ctypes.c_void_p
HANDLE = ctypes.c_void_p
ULONG = ctypes.c_ulong
USHORT = ctypes.c_ushort
ACCESS_MASK = ctypes.c_ulong
BOOLEAN = ctypes.c_ubyte

# NT status codes
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = ctypes.c_long(0xC0000022).value  # -1073741790

# ═══════════════════════════════════════════════════════════════════════════════
# NT Structures
# ═══════════════════════════════════════════════════════════════════════════════


class UNICODE_STRING(ctypes.Structure):
    """NT UNICODE_STRING structure."""

    _fields_ = [
        ("Length", USHORT),           # byte count (not including null)
        ("MaximumLength", USHORT),    # buffer capacity in bytes
        ("Buffer", ctypes.c_wchar_p),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    """NT OBJECT_ATTRIBUTES structure."""

    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    """NT IO_STATUS_BLOCK structure."""

    _fields_ = [
        ("Status", NTSTATUS),
        ("Information", ctypes.POINTER(ctypes.c_ulonglong)),
    ]


class LARGE_INTEGER(ctypes.Structure):
    """NT LARGE_INTEGER (64-bit signed)."""

    _fields_ = [
        ("QuadPart", ctypes.c_longlong),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    """Win32 SECURITY_ATTRIBUTES."""

    _fields_ = [
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", PVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    """Win32 STARTUPINFOW structure."""

    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", PVOID),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    """Win32 PROCESS_INFORMATION structure."""

    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Function type signatures for hooked APIs
# ═══════════════════════════════════════════════════════════════════════════════

# NtCreateFile(
#   OUT PHANDLE FileHandle,
#   IN ACCESS_MASK DesiredAccess,
#   IN POBJECT_ATTRIBUTES ObjectAttributes,
#   OUT PIO_STATUS_BLOCK IoStatusBlock,
#   IN PLARGE_INTEGER AllocationSize OPTIONAL,
#   IN ULONG FileAttributes,
#   IN ULONG ShareAccess,
#   IN ULONG CreateDisposition,
#   IN ULONG CreateOptions,
#   IN PVOID EaBuffer OPTIONAL,
#   IN ULONG EaLength
# )
NtCreateFile_t = ctypes.WINFUNCTYPE(
    NTSTATUS,                               # return
    ctypes.POINTER(HANDLE),                 # FileHandle
    ACCESS_MASK,                            # DesiredAccess
    ctypes.POINTER(OBJECT_ATTRIBUTES),      # ObjectAttributes
    ctypes.POINTER(IO_STATUS_BLOCK),        # IoStatusBlock
    ctypes.POINTER(LARGE_INTEGER),          # AllocationSize
    ULONG,                                  # FileAttributes
    ULONG,                                  # ShareAccess
    ULONG,                                  # CreateDisposition
    ULONG,                                  # CreateOptions
    PVOID,                                  # EaBuffer
    ULONG,                                  # EaLength
)

# NtOpenFile(
#   OUT PHANDLE FileHandle,
#   IN ACCESS_MASK DesiredAccess,
#   IN POBJECT_ATTRIBUTES ObjectAttributes,
#   OUT PIO_STATUS_BLOCK IoStatusBlock,
#   IN ULONG ShareAccess,
#   IN ULONG OpenOptions
# )
NtOpenFile_t = ctypes.WINFUNCTYPE(
    NTSTATUS,
    ctypes.POINTER(HANDLE),
    ACCESS_MASK,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ULONG,                                  # ShareAccess
    ULONG,                                  # OpenOptions
)

# NtDeleteFile(
#   IN POBJECT_ATTRIBUTES ObjectAttributes
# )
NtDeleteFile_t = ctypes.WINFUNCTYPE(
    NTSTATUS,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
)

# CreateProcessW(
#   LPCWSTR lpApplicationName,
#   LPWSTR lpCommandLine,
#   LPSECURITY_ATTRIBUTES lpProcessAttributes,
#   LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   BOOL bInheritHandles,
#   DWORD dwCreationFlags,
#   LPVOID lpEnvironment,
#   LPCWSTR lpCurrentDirectory,
#   LPSTARTUPINFOW lpStartupInfo,
#   LPPROCESS_INFORMATION lpProcessInformation
# )
CreateProcessW_t = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,                   # return
    ctypes.c_wchar_p,                       # lpApplicationName
    ctypes.c_wchar_p,                       # lpCommandLine
    PVOID,                                  # lpProcessAttributes
    PVOID,                                  # lpThreadAttributes
    ctypes.wintypes.BOOL,                   # bInheritHandles
    ctypes.wintypes.DWORD,                  # dwCreationFlags
    PVOID,                                  # lpEnvironment
    ctypes.c_wchar_p,                       # lpCurrentDirectory
    PVOID,                                  # lpStartupInfo
    PVOID,                                  # lpProcessInformation
)

# CreateProcessA (same signature but with LPCSTR/LPSTR)
CreateProcessA_t = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,
    ctypes.c_char_p,                        # lpApplicationName
    ctypes.c_char_p,                        # lpCommandLine
    PVOID,
    PVOID,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
    PVOID,
    ctypes.c_char_p,                        # lpCurrentDirectory
    PVOID,
    PVOID,
)

# ═══════════════════════════════════════════════════════════════════════════════
# File access mask constants (from Windows SDK)
# ═══════════════════════════════════════════════════════════════════════════════

FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_WRITE_DATA = 0x0002
FILE_ADD_FILE = 0x0002
FILE_APPEND_DATA = 0x0004
FILE_ADD_SUBDIRECTORY = 0x0004
FILE_READ_EA = 0x0008
FILE_WRITE_EA = 0x0010
FILE_EXECUTE = 0x0020
FILE_TRAVERSE = 0x0020
FILE_DELETE_CHILD = 0x0040
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_ATTRIBUTES = 0x0100

DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

# CreateProcess flags
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
