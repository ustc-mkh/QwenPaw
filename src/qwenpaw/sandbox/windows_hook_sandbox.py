# -*- coding: utf-8 -*-
"""Windows sandbox — DLL injection-based process isolation.

Uses a native DLL (sandbox_hook.dll) injected into the target process to
enforce filesystem access policies. The DLL hooks NT APIs and propagates
itself into all child processes via CreateProcessW/A interception.

  - **Filesystem isolation**: policy-driven allow/deny via hooked NtCreateFile,
    NtOpenFile, NtDeleteFile. No NTFS ACL modifications required.

  - **Child process propagation**: The DLL's CreateProcessW/A hooks
    automatically inject sandbox_hook.dll into every child process using
    CREATE_SUSPENDED + CreateRemoteThread + LoadLibraryW. This works for
    ANY child process regardless of language/runtime.

  - **Policy communication**: JSON policy in named shared memory section,
    identified by a session ID (environment variable).

  - **Violation reporting**: ring buffer in shared memory records all denied
    access attempts for post-execution inspection.

Architecture:
    1. Compile access policy from SandboxConfig into JSON
    2. Create named shared memory section with policy + violation ring buffer
    3. Create target process in CREATE_SUSPENDED state
    4. Inject sandbox_hook.dll via CreateRemoteThread(LoadLibraryW)
    5. Resume target process (hooks are active)
    6. Wait for completion, read stdout/stderr from pipes
    7. Read violation log from shared memory
    8. Cleanup: close shared memory handle

Advantages over pure-Python ctypes hooking:
    - Automatically propagates to ALL child processes (native, .NET, Python, etc.)
    - No Python interpreter needed in the target process
    - Lower overhead: hooks run in native code
    - More reliable: no GC/GIL interference with hook callbacks

Advantages over AppContainer:
    - No icacls / ACL modifications (instant setup/cleanup)
    - No AppContainer profile creation/deletion
    - Fine-grained path-level control with dynamic policy
    - No crash recovery needed (no persistent state)

Limitations:
    - Requires sandbox_hook.dll to be pre-built (MSVC or MinGW-w64 x64)
    - User-mode hooks can be bypassed by direct syscall (acceptable for
      LLM-generated code running through standard interpreters)

Requirements:
    - Windows 7+ (64-bit)
    - Python 3.8+
    - sandbox_hook.dll (x64, built from sandbox_hook.c)
    - Does NOT require Administrator privileges
"""

import asyncio
import base64
import ctypes
import json
import logging
import os
import re
import secrets
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import ExecutionResult, SandboxConfig
from .local_sandbox import LocalSandbox

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Win32 constants
# ═══════════════════════════════════════════════════════════════════════════════

# CreateProcess flags
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400

# STARTUPINFO flags
STARTF_USESTDHANDLES = 0x00000100

# WaitForSingleObject
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# Handle flags
HANDLE_FLAG_INHERIT = 0x00000001

# Memory allocation
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

# File mapping
FILE_MAP_ALL_ACCESS = 0x001F
FILE_MAP_READ = 0x0004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Shared memory protocol constants (must match sandbox_hook.h)
SANDBOX_MAGIC = 0x51574E50  # "QWNP"
SANDBOX_VERSION = 1
SANDBOX_VIOLATION_LOG_SIZE = 64 * 1024  # 64 KB
SANDBOX_HEADER_SIZE = 64  # bytes

# Policy flags (must match sandbox_hook.h)
POLICY_FLAG_DENY_NETWORK = 0x01
POLICY_FLAG_ALLOW_READ_ALL = 0x02

# Environment variable names
SANDBOX_ENV_VAR = "__QWENPAW_SANDBOX_SESSION"
SANDBOX_DLL_PATH_VAR = "__QWENPAW_SANDBOX_DLL_PATH"
SANDBOX_SHM_PREFIX = "Local\\QwenPaw_HookPolicy_"

# ═══════════════════════════════════════════════════════════════════════════════
# Win32 structures
# ═══════════════════════════════════════════════════════════════════════════════


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_uint32),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int32),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_uint32),
        ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32),
        ("dwYSize", ctypes.c_uint32),
        ("dwXCountChars", ctypes.c_uint32),
        ("dwYCountChars", ctypes.c_uint32),
        ("dwFillAttribute", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16),
        ("cbReserved2", ctypes.c_uint16),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Win32 DLL function declarations (lazy load)
# ═══════════════════════════════════════════════════════════════════════════════

_kernel32 = None

# Type aliases
_VP = ctypes.c_void_p
_U32 = ctypes.c_uint32
_I32 = ctypes.c_int32
_SZ = ctypes.c_size_t
_WP = ctypes.c_wchar_p
_PVP = ctypes.POINTER(ctypes.c_void_p)
_PU32 = ctypes.POINTER(ctypes.c_uint32)
_PSA = ctypes.POINTER(SECURITY_ATTRIBUTES)
_PPI = ctypes.POINTER(PROCESS_INFORMATION)

_DLL_SIGNATURES = {
    "kernel32": {
        "CreatePipe": ([_PVP, _PVP, _PSA, _U32], _I32),
        "SetHandleInformation": ([_VP, _U32, _U32], _I32),
        "CreateProcessW": (
            [_WP, _WP, _VP, _VP, _I32, _U32, _VP, _WP, _VP, _PPI],
            _I32,
        ),
        "WaitForSingleObject": ([_VP, _U32], _U32),
        "GetExitCodeProcess": ([_VP, _PU32], _I32),
        "TerminateProcess": ([_VP, _U32], _I32),
        "CloseHandle": ([_VP], _I32),
        "ReadFile": ([_VP, _VP, _U32, _PU32, _VP], _I32),
        "GetStdHandle": ([_I32], _VP),
        "CreateFileMappingW": ([_VP, _VP, _U32, _U32, _U32, _WP], _VP),
        "MapViewOfFile": ([_VP, _U32, _U32, _U32, _SZ], _VP),
        "UnmapViewOfFile": ([_VP], _I32),
        "VirtualAllocEx": ([_VP, _VP, _SZ, _U32, _U32], _VP),
        "VirtualFreeEx": ([_VP, _VP, _SZ, _U32], _I32),
        "WriteProcessMemory": ([_VP, _VP, _VP, _SZ, _PVP], _I32),
        "CreateRemoteThread": ([_VP, _VP, _SZ, _VP, _VP, _U32, _PU32], _VP),
        "ResumeThread": ([_VP], _U32),
        "GetModuleHandleW": ([_WP], _VP),
        "GetProcAddress": ([_VP, ctypes.c_char_p], _VP),
    },
}


def _load_dlls():
    """Lazy-load Win32 DLLs and configure function signatures."""
    global _kernel32
    if _kernel32 is not None:
        return

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    for func_name, (argtypes, restype) in _DLL_SIGNATURES["kernel32"].items():
        fn = getattr(_kernel32, func_name)
        fn.argtypes = argtypes
        fn.restype = restype


# ═══════════════════════════════════════════════════════════════════════════════
# Cached encoding values (constant per process lifetime)
# ═══════════════════════════════════════════════════════════════════════════════

_cached_oem_encoding: Optional[str] = None
_cached_ansi_encoding: Optional[str] = None


def _get_system_ansi_encoding() -> str:
    """Return the codec name for the system ANSI code page."""
    global _cached_ansi_encoding
    if _cached_ansi_encoding is not None:
        return _cached_ansi_encoding
    try:
        acp = ctypes.windll.kernel32.GetACP()
        _cached_ansi_encoding = f"cp{acp}"
    except (AttributeError, OSError):
        _cached_ansi_encoding = "utf-8"
    return _cached_ansi_encoding


def _get_system_oem_encoding() -> str:
    """Return the codec name for the system OEM code page."""
    global _cached_oem_encoding
    if _cached_oem_encoding is not None:
        return _cached_oem_encoding
    try:
        oem_cp = ctypes.windll.kernel32.GetOEMCP()
        _cached_oem_encoding = f"cp{oem_cp}"
    except (AttributeError, OSError):
        _cached_oem_encoding = _get_system_ansi_encoding()
    return _cached_oem_encoding


# ═══════════════════════════════════════════════════════════════════════════════
# System path helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _windows_system_read_paths() -> List[str]:
    """Return Windows system paths that should always be readable."""
    windir = os.environ.get("SystemRoot", "C:\\Windows")
    progfiles = os.environ.get("ProgramFiles", "C:\\Program Files")
    progfiles86 = os.environ.get(
        "ProgramFiles(x86)",
        "C:\\Program Files (x86)",
    )
    paths = [windir, progfiles, progfiles86]
    return [p for p in paths if os.path.isdir(p)]


def _expand_deny_paths(deny_paths: List[str]) -> List[str]:
    """Expand user-relative deny paths."""
    return [
        os.path.expanduser(path) if path.startswith("~") else path
        for path in deny_paths
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# DLL path resolution
# ═══════════════════════════════════════════════════════════════════════════════


def _find_sandbox_dll() -> Optional[str]:
    """Locate sandbox_hook.dll relative to this package.

    Search order:
      1. Same directory as this module (windows_dll_hook/)
      2. Package root sandbox/ directory
      3. QWENPAW_SANDBOX_DLL_PATH environment variable
    """
    # Check in the dll_hook package directory
    pkg_dir = Path(__file__).parent / "windows_dll_hook"
    dll_path = pkg_dir / "sandbox_hook.dll"
    if dll_path.exists():
        return str(dll_path)

    # Check in the sandbox package root
    sandbox_dir = Path(__file__).parent
    dll_path = sandbox_dir / "sandbox_hook.dll"
    if dll_path.exists():
        return str(dll_path)

    # Check environment variable
    env_path = os.environ.get("QWENPAW_SANDBOX_DLL_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Policy compilation
# ═══════════════════════════════════════════════════════════════════════════════


def _compile_policy(
    config: SandboxConfig,
    session_id: str,
) -> bytes:
    """Compile SandboxConfig into JSON policy bytes for the sandbox DLL.

    Rule priority (evaluated in order by the DLL):
      1. deny rules (access="deny") -- always block
      2. explicit mounts/workspace -- longest prefix match
      3. system paths -- read+execute
      4. default: allow_read_all flag controls fallback behavior

    Args:
        config: Sandbox configuration.
        session_id: Unique session identifier.

    Returns:
        UTF-8 encoded JSON bytes.
    """
    rules: List[Dict[str, str]] = []

    # 1. Deny paths (highest priority)
    deny_expanded = _expand_deny_paths(config.deny_paths)
    for p in deny_expanded:
        rules.append({"path": os.path.normpath(p), "access": "deny"})

    # 2. Workspace directory (always full write access, matching Linux sandbox)
    ws = config.workspace_dir
    if ws:
        rules.append({"path": os.path.normpath(ws), "access": "rw"})

    # 3. Explicit mounts
    for mount in config.mounts:
        norm_mount = os.path.normpath(mount.path)
        # Skip if already covered by workspace
        if ws and os.path.normcase(norm_mount) == os.path.normcase(ws):
            continue
        if mount.writable:
            access = "rw"
        elif mount.executable:
            access = "rx"
        else:
            access = "r"
        rules.append({"path": norm_mount, "access": access})

    # 4. System paths (always read+execute)
    for sp in _windows_system_read_paths():
        rules.append({"path": os.path.normpath(sp), "access": "rx"})

    # 5. TEMP directory (writable)
    temp_dir = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp_dir and os.path.isdir(temp_dir):
        rules.append({"path": os.path.normpath(temp_dir), "access": "rw"})

    # 6. Python installation directory (read+execute)
    python_dir = os.path.dirname(sys.executable)
    if python_dir:
        rules.append({"path": os.path.normpath(python_dir), "access": "rx"})

    policy = {
        "session_id": session_id,
        "rules": rules,
        "allow_read_all": config.allow_read_all,
        "deny_network": not bool(config.network_allow),
    }

    return json.dumps(policy, ensure_ascii=True).encode("utf-8")


# ═══════════════════════════════════════════════════════════════════════════════
# Shared memory management
# ═══════════════════════════════════════════════════════════════════════════════


def _create_shared_memory(
    session_id: str,
    policy_bytes: bytes,
    config: SandboxConfig,
) -> Tuple[ctypes.c_void_p, ctypes.c_void_p]:
    """Create named shared memory section with policy and violation ring buffer.

    Layout (must match sandbox_hook.h SANDBOX_POLICY_HEADER):
      [0..63]   Header (64 bytes)
      [64..64+policy_length-1]  UTF-8 JSON policy
      [64+policy_length..end]   Violation ring buffer (64KB)

    The shared memory is created with read-write access for the parent process,
    but child processes open it with FILE_MAP_READ for the policy section.
    The violation log region uses InterlockedIncrement which works on read-only
    mapped pages because the underlying section is PAGE_READWRITE — the DLL
    opens with FILE_MAP_ALL_ACCESS is restricted to FILE_MAP_READ plus
    write access only to the violation log area via section offset mapping.

    Note: Full FILE_MAP_ALL_ACCESS is required for the DLL because
    InterlockedIncrement on violation_count/violation_write_pos needs write
    access. Security is enforced by the DLL only writing to the violation
    log fields, not the policy. A malicious child could modify the policy
    in shared memory; to mitigate, the DLL parses the policy only once
    on DLL_PROCESS_ATTACH before user code runs.

    Returns:
        (shm_handle, shm_view) -- both must be closed/unmapped on cleanup.
    """
    total_size = (
        SANDBOX_HEADER_SIZE + len(policy_bytes) + SANDBOX_VIOLATION_LOG_SIZE
    )
    shm_name = f"{SANDBOX_SHM_PREFIX}{session_id}"

    shm_handle = _kernel32.CreateFileMappingW(
        ctypes.c_void_p(INVALID_HANDLE_VALUE),
        None,
        PAGE_READWRITE,
        0,
        total_size,
        shm_name,
    )
    if not shm_handle:
        raise OSError(
            f"CreateFileMappingW failed: error={ctypes.get_last_error()}"
        )

    shm_view = _kernel32.MapViewOfFile(
        shm_handle,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        ctypes.c_size_t(total_size),
    )
    if not shm_view:
        _kernel32.CloseHandle(shm_handle)
        raise OSError(f"MapViewOfFile failed: error={ctypes.get_last_error()}")

    # Build header - derive flags directly from config (no redundant JSON parse)
    violation_log_offset = SANDBOX_HEADER_SIZE + len(policy_bytes)
    flags = 0
    if config.allow_read_all:
        flags |= POLICY_FLAG_ALLOW_READ_ALL
    if not config.network_allow:
        flags |= POLICY_FLAG_DENY_NETWORK

    header = struct.pack(
        "<IIIIIIII8I",
        SANDBOX_MAGIC,
        SANDBOX_VERSION,
        len(policy_bytes),
        flags,
        violation_log_offset,
        SANDBOX_VIOLATION_LOG_SIZE,
        0,  # violation_count
        0,  # violation_write_pos
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,  # reserved[8]
    )

    ctypes.memmove(shm_view, header, len(header))
    ctypes.memmove(
        ctypes.c_void_p(shm_view + SANDBOX_HEADER_SIZE),
        policy_bytes,
        len(policy_bytes),
    )
    ctypes.memset(
        ctypes.c_void_p(shm_view + violation_log_offset),
        0,
        SANDBOX_VIOLATION_LOG_SIZE,
    )

    return ctypes.c_void_p(shm_handle), ctypes.c_void_p(shm_view)


_VIOLATION_ACCESS_NAMES = {
    0x0001: "read",
    0x0002: "write",
    0x0004: "delete",
    0x0008: "execute",
    0x0010: "network",
    0x0020: "symlink",
}

# Violation entry header: total_size(4) + timestamp(4) + pid(4) + tid(4)
#                         + path_length(2) + access_type(2) = 20 bytes
_VIOLATION_ENTRY_HDR_SIZE = 20


def _read_violations(shm_view: ctypes.c_void_p) -> Optional[str]:
    """Read violation log from shared memory after process exit.

    Reads all available entries from the ring buffer and returns a summary
    string with unique violations.
    """
    if not shm_view:
        return None

    # Extract raw integer address for pointer arithmetic
    if isinstance(shm_view, ctypes.c_void_p):
        base = shm_view.value
    else:
        base = int(shm_view)
    if not base:
        return None

    count_bytes = (ctypes.c_byte * 4)()
    ctypes.memmove(count_bytes, ctypes.c_void_p(base + 24), 4)
    violation_count = struct.unpack("<I", bytes(count_bytes))[0]

    if violation_count == 0:
        return None

    offsets_bytes = (ctypes.c_byte * 8)()
    ctypes.memmove(offsets_bytes, ctypes.c_void_p(base + 16), 8)
    log_offset, log_size = struct.unpack("<II", bytes(offsets_bytes))

    # Read all entries from the ring buffer
    violations: List[str] = []
    pos = 0
    max_entries = min(violation_count, 64)  # cap to avoid infinite loop

    for _ in range(max_entries):
        if pos + _VIOLATION_ENTRY_HDR_SIZE > log_size:
            break

        entry_header = (ctypes.c_byte * _VIOLATION_ENTRY_HDR_SIZE)()
        ctypes.memmove(
            entry_header,
            ctypes.c_void_p(base + log_offset + pos),
            _VIOLATION_ENTRY_HDR_SIZE,
        )

        total_size, timestamp, pid, tid, path_length, access_type = (
            struct.unpack("<IIIIHH", bytes(entry_header))
        )

        if total_size == 0 or path_length == 0:
            break
        if pos + total_size > log_size:
            break

        path_byte_len = path_length * 2
        remaining = log_size - pos - _VIOLATION_ENTRY_HDR_SIZE
        if path_byte_len > remaining:
            path_byte_len = remaining

        path_bytes = (ctypes.c_byte * path_byte_len)()
        ctypes.memmove(
            path_bytes,
            ctypes.c_void_p(
                base + log_offset + pos + _VIOLATION_ENTRY_HDR_SIZE
            ),
            path_byte_len,
        )
        try:
            path_str = bytes(path_bytes).decode("utf-16-le").rstrip("\x00")
        except (UnicodeDecodeError, ValueError):
            path_str = "<unreadable path>"

        access_str = _VIOLATION_ACCESS_NAMES.get(
            access_type, f"access_type=0x{access_type:04x}"
        )
        violations.append(f"{access_str} denied on '{path_str}' (pid={pid})")

        pos += total_size

    if not violations:
        return f"Sandbox violation detected ({violation_count} total)"

    # Deduplicate and summarize
    unique = list(dict.fromkeys(violations))
    summary = "; ".join(unique[:5])
    if violation_count > len(unique):
        summary += f" (+{violation_count - len(unique)} more)"
    return f"Sandbox violations: {summary}"


# ═══════════════════════════════════════════════════════════════════════════════
# Pipe I/O
# ═══════════════════════════════════════════════════════════════════════════════


def _create_pipes() -> Tuple[ctypes.c_void_p, ctypes.c_void_p]:
    """Create an inheritable pipe pair for capturing child process output."""
    read_h = ctypes.c_void_p()
    write_h = ctypes.c_void_p()

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = 1
    sa.lpSecurityDescriptor = None

    ok = _kernel32.CreatePipe(
        ctypes.byref(read_h),
        ctypes.byref(write_h),
        ctypes.byref(sa),
        0,
    )
    if not ok:
        raise OSError(f"CreatePipe failed: error={ctypes.get_last_error()}")

    _kernel32.SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0)
    return read_h, write_h


def _read_pipe(handle: ctypes.c_void_p) -> str:
    """Read all data from a pipe until EOF.

    Decoding strategy: OEM -> ANSI -> UTF-8 with replacement.
    """
    ERROR_BROKEN_PIPE = 109
    chunks: List[bytes] = []
    buf_size = 8192
    buf = (ctypes.c_ubyte * buf_size)()
    bytes_read = ctypes.c_uint32()

    while True:
        ok = _kernel32.ReadFile(
            handle, buf, buf_size, ctypes.byref(bytes_read), None
        )
        if not ok:
            if bytes_read.value > 0:
                chunks.append(bytes(buf[: bytes_read.value]))
            err = ctypes.get_last_error()
            if err == ERROR_BROKEN_PIPE:
                break
            break
        if bytes_read.value == 0:
            break
        chunks.append(bytes(buf[: bytes_read.value]))

    raw = b"".join(chunks)

    # Detect UTF-16LE: if data has frequent \x00 bytes at odd positions,
    # it's likely UTF-16LE (PowerShell outputs UTF-16LE in some configurations)
    if len(raw) >= 2:
        # Check for UTF-16LE BOM
        if raw[:2] == b"\xff\xfe":
            try:
                return raw.decode("utf-16-le")
            except (UnicodeDecodeError, ValueError):
                pass
        # Heuristic: if >25% of bytes at odd positions are \x00, it's UTF-16LE
        elif len(raw) >= 4:
            sample = raw[: min(64, len(raw))]
            null_at_odd = sum(
                1 for i in range(1, len(sample), 2) if sample[i] == 0
            )
            total_odd = len(sample) // 2
            if total_odd > 0 and null_at_odd > total_odd * 0.25:
                try:
                    return raw.decode("utf-16-le")
                except (UnicodeDecodeError, ValueError):
                    pass

    for enc in (
        _get_system_oem_encoding(),
        _get_system_ansi_encoding(),
        "utf-8",
    ):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════════
# PowerShell command helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _build_powershell_command_line(cmd: str, cwd: Optional[str] = None) -> str:
    """Build a PowerShell command line using -EncodedCommand."""
    if cwd:
        escaped_cwd = cwd.replace("'", "''")
        set_location = f"Set-Location -LiteralPath '{escaped_cwd}'\n"
    else:
        set_location = ""

    script = (
        "$ProgressPreference = 'SilentlyContinue'\n"
        f"{set_location}"
        f"{cmd}\n"
        "if ($? -eq $false) {\n"
        "  $__qwenpaw_code = if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }\n"
        "} else {\n"
        "  $__qwenpaw_code = $LASTEXITCODE\n"
        "  if ($null -eq $__qwenpaw_code) { $__qwenpaw_code = 0 }\n"
        "}\n"
        "exit $__qwenpaw_code\n"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return (
        "powershell.exe -NoProfile -NonInteractive "
        f"-ExecutionPolicy Bypass -EncodedCommand {encoded}"
    )


def _clean_powershell_stderr(stderr: str) -> str:
    """Clean PowerShell CLIXML stderr output, preserving error messages."""
    if not stderr:
        return stderr

    if "#< CLIXML" not in stderr:
        return stderr.strip()

    error_parts: List[str] = []
    for match in re.finditer(r'<S S="Error">(.*?)</S>', stderr, re.DOTALL):
        text = match.group(1)
        text = text.replace("_x000D__x000A_", "\n")
        text = text.replace("_x000D_", "\r")
        text = text.replace("_x000A_", "\n")
        error_parts.append(text)

    if error_parts:
        return "".join(error_parts).strip()

    cleaned = stderr
    cleaned = cleaned.replace("#< CLIXML", "")
    cleaned = re.sub(r"</?Objs[^>]*>", "", cleaned)
    cleaned = re.sub(r"<PR [^>]*/>", "", cleaned)
    cleaned = re.sub(r'<S S="[^"]*">', "", cleaned)
    cleaned = re.sub(r"</S>", "", cleaned)
    return cleaned.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# DLL injection
# ═══════════════════════════════════════════════════════════════════════════════


def _inject_dll(
    process_handle: ctypes.c_void_p,
    dll_path: str,
) -> bool:
    """Inject a DLL into a suspended process via CreateRemoteThread + LoadLibraryW.

    Args:
        process_handle: Handle to the target process (must have appropriate access).
        dll_path: Full path to the DLL to inject.

    Returns:
        True if injection succeeded.
    """
    # Encode DLL path as UTF-16LE (for LoadLibraryW)
    dll_path_bytes = (dll_path + "\0").encode("utf-16-le")
    path_size = len(dll_path_bytes)

    # Allocate memory in target process for the DLL path
    remote_buf = _kernel32.VirtualAllocEx(
        process_handle,
        None,
        ctypes.c_size_t(path_size),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
    if not remote_buf:
        logger.error(
            "VirtualAllocEx failed: error=%d", ctypes.get_last_error()
        )
        return False

    # Write DLL path to target process memory
    written = ctypes.c_void_p()
    ok = _kernel32.WriteProcessMemory(
        process_handle,
        remote_buf,
        dll_path_bytes,
        ctypes.c_size_t(path_size),
        ctypes.byref(written),
    )
    if not ok:
        logger.error(
            "WriteProcessMemory failed: error=%d", ctypes.get_last_error()
        )
        _kernel32.VirtualFreeEx(
            process_handle, remote_buf, ctypes.c_size_t(0), MEM_RELEASE
        )
        return False

    # Get LoadLibraryW address (same across processes due to ASLR consistency)
    h_kernel32 = _kernel32.GetModuleHandleW("kernel32.dll")
    load_library_addr = _kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
    if not load_library_addr:
        logger.error("Failed to resolve LoadLibraryW address")
        _kernel32.VirtualFreeEx(
            process_handle, remote_buf, ctypes.c_size_t(0), MEM_RELEASE
        )
        return False

    # Create remote thread calling LoadLibraryW(dll_path)
    thread_id = ctypes.c_uint32()
    h_thread = _kernel32.CreateRemoteThread(
        process_handle,
        None,
        ctypes.c_size_t(0),
        load_library_addr,
        remote_buf,
        0,
        ctypes.byref(thread_id),
    )
    if not h_thread:
        logger.error(
            "CreateRemoteThread failed: error=%d", ctypes.get_last_error()
        )
        _kernel32.VirtualFreeEx(
            process_handle, remote_buf, ctypes.c_size_t(0), MEM_RELEASE
        )
        return False

    # Wait for DLL to load (timeout 10s)
    _kernel32.WaitForSingleObject(h_thread, 10000)
    _kernel32.CloseHandle(h_thread)

    # Free remote buffer
    _kernel32.VirtualFreeEx(
        process_handle, remote_buf, ctypes.c_size_t(0), MEM_RELEASE
    )

    logger.debug("DLL injected successfully: %s", dll_path)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Process launch with DLL injection
# ═══════════════════════════════════════════════════════════════════════════════


def _launch_sandboxed_process_sync(
    cmd: str,
    cwd: str,
    session_id: str,
    dll_path: str,
    env_vars: Optional[Dict[str, str]],
    timeout_ms: int,
) -> Tuple[int, str, str, bool]:
    """Launch a process with DLL injection for sandboxing.

    Strategy:
      1. Create target process in CREATE_SUSPENDED state
      2. Inject sandbox_hook.dll via CreateRemoteThread + LoadLibraryW
      3. Resume the main thread
      4. Wait for completion, read output

    Returns:
        (exit_code, stdout, stderr, timed_out)
    """
    # 1. Create pipes for stdout/stderr capture
    stdout_rd, stdout_wr = _create_pipes()
    stderr_rd, stderr_wr = _create_pipes()

    try:
        # 2. Build environment block (inject session ID and DLL path)
        merged = dict(os.environ)
        if env_vars:
            merged.update(env_vars)
        merged[SANDBOX_ENV_VAR] = session_id
        merged[SANDBOX_DLL_PATH_VAR] = dll_path
        # Enable debug logging in DLL if parent has DEBUG level
        if logger.isEnabledFor(logging.DEBUG):
            merged["QWENPAW_HOOK_DEBUG"] = "1"
        pairs = [f"{k}={v}" for k, v in merged.items()]
        block_str = "\0".join(pairs) + "\0\0"
        env_block = ctypes.create_unicode_buffer(block_str)

        # 3. Build command line (wrap in cmd.exe for shell execution)
        cmd_line = _build_powershell_command_line(cmd, cwd)

        # 4. Fill STARTUPINFOW
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = STARTF_USESTDHANDLES
        si.hStdInput = _kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        si.hStdOutput = stdout_wr
        si.hStdError = stderr_wr

        # 5. CreateProcessW in SUSPENDED state
        pi = PROCESS_INFORMATION()
        creation_flags = (
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
        )

        ok = _kernel32.CreateProcessW(
            None,
            cmd_line,
            None,
            None,
            1,  # bInheritHandles = TRUE
            creation_flags,
            ctypes.cast(env_block, ctypes.c_void_p),
            cwd,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(
                f"CreateProcessW failed: error={err} "
                f"({ctypes.FormatError(err)})"
            )

        # 6. Inject DLL into the suspended process
        injection_ok = _inject_dll(pi.hProcess, dll_path)
        if not injection_ok:
            # Terminate the process — running without sandbox is unsafe
            logger.error(
                "DLL injection failed, terminating unsandboxed process"
            )
            _kernel32.TerminateProcess(pi.hProcess, 1)
            _kernel32.CloseHandle(pi.hProcess)
            _kernel32.CloseHandle(pi.hThread)
            raise OSError(
                "Sandbox DLL injection failed. "
                "Cannot execute command without isolation."
            )

        # 7. Resume the main thread
        _kernel32.ResumeThread(pi.hThread)

        # 8. Close child-side write handles
        _kernel32.CloseHandle(stdout_wr)
        stdout_wr = None
        _kernel32.CloseHandle(stderr_wr)
        stderr_wr = None

        # 9. Read pipes concurrently (avoids deadlock when both buffers fill)
        stdout_data = ""
        stderr_data = ""

        def _drain_stdout():
            nonlocal stdout_data
            stdout_data = _read_pipe(stdout_rd)

        def _drain_stderr():
            nonlocal stderr_data
            stderr_data = _read_pipe(stderr_rd)

        reader_stdout = threading.Thread(target=_drain_stdout, daemon=True)
        reader_stderr = threading.Thread(target=_drain_stderr, daemon=True)
        reader_stdout.start()
        reader_stderr.start()

        # 10. Wait for process completion
        wait_result = _kernel32.WaitForSingleObject(pi.hProcess, timeout_ms)
        timed_out = wait_result == WAIT_TIMEOUT
        if timed_out:
            _kernel32.TerminateProcess(pi.hProcess, 1)

        # Wait for readers to finish (pipes close after process exits)
        reader_stdout.join(timeout=5)
        reader_stderr.join(timeout=5)

        # 11. Get exit code
        exit_code = ctypes.c_uint32()
        _kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))

        # 12. Cleanup handles
        _kernel32.CloseHandle(pi.hProcess)
        _kernel32.CloseHandle(pi.hThread)

        return (
            exit_code.value if not timed_out else -1,
            stdout_data,
            stderr_data,
            timed_out,
        )
    finally:
        if stdout_wr is not None:
            _kernel32.CloseHandle(stdout_wr)
        if stderr_wr is not None:
            _kernel32.CloseHandle(stderr_wr)
        _kernel32.CloseHandle(stdout_rd)
        _kernel32.CloseHandle(stderr_rd)


# ═══════════════════════════════════════════════════════════════════════════════
# WindowsHookSandbox class
# ═══════════════════════════════════════════════════════════════════════════════


class WindowsHookSandbox(LocalSandbox):
    """Windows sandbox using DLL injection for NT API hooking.

    Injects sandbox_hook.dll into the target process and all its children.
    The DLL hooks NtCreateFile/NtOpenFile/NtDeleteFile and propagates itself
    into child processes via CreateProcessW/A hooks.

    This solves the child-process sandboxing problem: unlike the pure-Python
    ctypes approach, native DLL injection works for any child process
    regardless of its runtime (cmd.exe, python.exe, node.exe, etc.).

    Lifecycle: per-tool-call (create shared memory, execute, cleanup).
    """

    def __init__(self, config: SandboxConfig):
        self._config = config
        self._session_id: str = ""
        self._shm_handle: Optional[ctypes.c_void_p] = None
        self._shm_view: Optional[ctypes.c_void_p] = None
        self._dll_path: Optional[str] = None
        self._initialized: bool = False

    async def _initialize(self) -> None:
        if self._initialized:
            return

        if sys.platform != "win32":
            raise RuntimeError(
                "WindowsHookSandbox requires Windows. "
                "Use SandboxMode.NONE for unisolated execution.",
            )

        _load_dlls()

        # Locate the DLL
        self._dll_path = _find_sandbox_dll()
        if not self._dll_path:
            raise RuntimeError(
                "sandbox_hook.dll not found. Build it from "
                "src/qwenpaw/sandbox/windows_dll_hook/sandbox_hook.c "
                "using MSVC or MinGW-w64 (x64). Place the DLL in the "
                "windows_dll_hook/ directory or set QWENPAW_SANDBOX_DLL_PATH."
            )

        # Generate unique session ID
        self._session_id = secrets.token_hex(12)

        # Compile policy
        policy_bytes = _compile_policy(self._config, self._session_id)

        # Create shared memory
        self._shm_handle, self._shm_view = _create_shared_memory(
            self._session_id, policy_bytes, self._config
        )

        self._initialized = True
        logger.info(
            "WindowsHookSandbox initialized: session=%s, dll=%s",
            self._session_id,
            self._dll_path,
        )

    async def __aenter__(self):
        await self._initialize()
        return self

    def _reset_violation_buffer(self) -> None:
        """Reset the violation count and write position before each execution.

        This prevents stale violations from a previous execute() call from
        being reported in subsequent calls.
        """
        if not self._shm_view:
            return
        base = (
            self._shm_view.value
            if isinstance(self._shm_view, ctypes.c_void_p)
            else int(self._shm_view)
        )
        if not base:
            return
        # Zero out violation_count (offset 24) and violation_write_pos (offset 28)
        zero = struct.pack("<II", 0, 0)
        ctypes.memmove(ctypes.c_void_p(base + 24), zero, 8)

    async def execute(
        self,
        cmd: str,
        cwd: Optional[str] = None,
    ) -> ExecutionResult:
        start = time.monotonic()
        try:
            await self._initialize()
            self._reset_violation_buffer()
            cwd = cwd or self._config.workspace_dir
            timeout_ms = self._config.timeout_seconds * 1000

            loop = asyncio.get_event_loop()
            # Two timeout layers: Win32 WaitForSingleObject (timeout_ms) handles
            # normal cases; asyncio wait_for (+10s) guards against the executor
            # thread hanging after process exit (e.g., pipe read deadlock).
            exit_code, stdout, stderr, timed_out = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    _launch_sandboxed_process_sync,
                    cmd,
                    cwd,
                    self._session_id,
                    self._dll_path,
                    self._config.env_vars or None,
                    timeout_ms,
                ),
                timeout=self._config.timeout_seconds + 10,
            )
            duration_ms = int((time.monotonic() - start) * 1000)

            # Clean PowerShell CLIXML noise from stderr
            stderr = _clean_powershell_stderr(stderr)

            # Check for violations in shared memory
            violation = None
            if not timed_out:
                violation = _read_violations(self._shm_view)

            # Fallback: detect from stderr keywords
            if not violation and not timed_out and exit_code != 0:
                stderr_lower = stderr.lower()
                if any(
                    kw in stderr_lower
                    for kw in (
                        "access is denied",
                        "access denied",
                        "permission denied",
                        "not have permission",
                        "unauthorized",
                    )
                ):
                    violation = stderr.strip()

            return ExecutionResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                duration_ms=duration_ms,
                sandbox_violation=violation,
            )
        except asyncio.TimeoutError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="Command timed out",
                timed_out=True,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms,
            )

    async def stop(self) -> None:
        """No-op: process lifetime is managed by the sync launcher."""
        return None

    async def cleanup(self) -> None:
        """Release shared memory. No filesystem modifications to undo."""
        if _kernel32 is not None:
            if self._shm_view:
                _kernel32.UnmapViewOfFile(self._shm_view)
            if self._shm_handle:
                _kernel32.CloseHandle(self._shm_handle)
        self._shm_view = None
        self._shm_handle = None
        self._session_id = ""
        self._initialized = False

    async def __aexit__(self, exc_type, exc, tb):
        await self.cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# Platform probe
# ═══════════════════════════════════════════════════════════════════════════════


def probe_windows_hook() -> Tuple[bool, str]:
    """Probe Windows hook sandbox capabilities.

    Returns:
        (available, reason)
        - available: True if platform is win32, Python is 64-bit, and DLL exists
        - reason: Human-readable description
    """
    if sys.platform != "win32":
        return False, "Not running on Windows"

    if struct.calcsize("P") * 8 != 64:
        return False, "Requires 64-bit Python (DLL hooks are x64 only)"

    dll_path = _find_sandbox_dll()
    if not dll_path:
        return False, (
            "sandbox_hook.dll not found. Build from "
            "windows_dll_hook/sandbox_hook.c (MSVC/MinGW-w64 x64)"
        )

    return True, (
        f"Windows DLL injection sandbox: "
        f"NT API hooking via injected DLL ({dll_path}). "
        f"Propagates to all child processes automatically."
    )
