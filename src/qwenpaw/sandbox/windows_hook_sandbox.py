# -*- coding: utf-8 -*-
"""Windows sandbox — Pure Python ctypes inline hooking process isolation.

Uses a Python-based sandbox runner that installs inline hooks on NT APIs
to enforce filesystem access policies. No compiled DLL or external
libraries required.

  - **Filesystem isolation**: policy-driven allow/deny via hooked NtCreateFile,
    NtOpenFile, NtDeleteFile. No NTFS ACL modifications required.

  - **Recursive sandboxing**: CreateProcessW/A hooks automatically wrap
    child processes through the same sandbox runner.

  - **Policy communication**: JSON policy in named shared memory section,
    identified by a session ID.

  - **Violation reporting**: ring buffer in shared memory records all denied
    access attempts for post-execution inspection.

Architecture:
    1. Compile access policy from SandboxConfig into JSON
    2. Create named shared memory section with policy + violation ring buffer
    3. Launch sandbox_runner.py as child process (hooks install in runner)
    4. Runner executes target command with hooks active
    5. Wait for completion, read stdout/stderr from pipes
    6. Read violation log from shared memory
    7. Cleanup: close shared memory handle (OS reclaims automatically)

Advantages over AppContainer:
    - No icacls / ACL modifications (instant setup/cleanup)
    - No AppContainer profile creation/deletion
    - No crash recovery needed (no persistent state)
    - Fine-grained path-level control with dynamic policy
    - Pure Python: fully debuggable with print/logging/pdb
    - No external compilation toolchain required

Limitations:
    - User-mode hooks can be bypassed by direct syscall (not a concern for
      LLM-generated code running through standard interpreters)

Requirements:
    - Windows 7+ (64-bit)
    - Python 3.8+ (same interpreter used for both parent and runner)
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
import time
from typing import Dict, List, Optional, Tuple

from .config import ExecutionResult, SandboxConfig
from .local_sandbox import LocalSandbox

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Win32 constants
# ═══════════════════════════════════════════════════════════════════════════════

# CreateProcess flags
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400

# STARTUPINFO flags
STARTF_USESTDHANDLES = 0x00000100

# WaitForSingleObject
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# Handle flags
HANDLE_FLAG_INHERIT = 0x00000001

# File mapping
PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0x001F
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Shared memory protocol constants (must match sandbox_hook.h)
SANDBOX_MAGIC = 0x51574E50  # "QWNP"
SANDBOX_VERSION = 1
SANDBOX_VIOLATION_LOG_SIZE = 64 * 1024  # 64 KB
SANDBOX_HEADER_SIZE = 64  # bytes

# Policy flags (must match sandbox_hook.h)
POLICY_FLAG_DENY_NETWORK = 0x01
POLICY_FLAG_ALLOW_READ_ALL = 0x02

# Environment variable name for session ID
SANDBOX_ENV_VAR = "__QWENPAW_SANDBOX_SESSION"
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
# Policy compilation
# ═══════════════════════════════════════════════════════════════════════════════


def _compile_policy(
    config: SandboxConfig,
    session_id: str,
) -> bytes:
    """Compile SandboxConfig into JSON policy bytes for the sandbox runner.

    Rule priority (evaluated in order by the runner):
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

    # 2. Workspace directory
    ws = config.workspace_dir
    if ws:
        ws_writable = any(
            os.path.normcase(m.path) == os.path.normcase(ws) and m.writable
            for m in config.mounts
        )
        rules.append({
            "path": os.path.normpath(ws),
            "access": "rw" if ws_writable else "rx",
        })

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

    # 6. Python installation directory (read+execute, needed by sandbox_runner)
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
) -> Tuple[ctypes.c_void_p, ctypes.c_void_p]:
    """Create named shared memory section with policy and violation ring buffer.

    Layout (must match sandbox_hook.h SANDBOX_POLICY_HEADER):
      [0..63]   Header (64 bytes)
      [64..64+policy_length-1]  UTF-8 JSON policy
      [64+policy_length..end]   Violation ring buffer (64KB)

    Returns:
        (shm_handle, shm_view) -- both must be closed/unmapped on cleanup.
    """
    total_size = SANDBOX_HEADER_SIZE + len(policy_bytes) + SANDBOX_VIOLATION_LOG_SIZE
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
        raise OSError(
            f"MapViewOfFile failed: error={ctypes.get_last_error()}"
        )

    # Build header
    violation_log_offset = SANDBOX_HEADER_SIZE + len(policy_bytes)
    flags = 0
    policy_dict = json.loads(policy_bytes)
    if policy_dict.get("allow_read_all", False):
        flags |= POLICY_FLAG_ALLOW_READ_ALL
    if policy_dict.get("deny_network", False):
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
        0, 0, 0, 0, 0, 0, 0, 0,  # reserved[8]
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


def _read_violations(shm_view: ctypes.c_void_p) -> Optional[str]:
    """Read violation log from shared memory after process exit."""
    if not shm_view:
        return None

    count_bytes = (ctypes.c_byte * 4)()
    ctypes.memmove(count_bytes, ctypes.c_void_p(shm_view + 24), 4)
    violation_count = struct.unpack("<I", bytes(count_bytes))[0]

    if violation_count == 0:
        return None

    offsets_bytes = (ctypes.c_byte * 8)()
    ctypes.memmove(offsets_bytes, ctypes.c_void_p(shm_view + 16), 8)
    log_offset, log_size = struct.unpack("<II", bytes(offsets_bytes))

    entry_header_size = 20  # total_size + timestamp + pid + tid + path_length + access_type
    entry_header = (ctypes.c_byte * entry_header_size)()
    ctypes.memmove(entry_header, ctypes.c_void_p(shm_view + log_offset), entry_header_size)

    total_size, timestamp, pid, tid, path_length, access_type = struct.unpack(
        "<IIIIHH", bytes(entry_header)
    )

    if path_length == 0 or total_size == 0:
        return f"Sandbox violation detected ({violation_count} total)"

    path_byte_len = path_length * 2
    if path_byte_len > log_size - entry_header_size:
        path_byte_len = log_size - entry_header_size

    path_bytes = (ctypes.c_byte * path_byte_len)()
    ctypes.memmove(
        path_bytes,
        ctypes.c_void_p(shm_view + log_offset + entry_header_size),
        path_byte_len,
    )
    try:
        path_str = bytes(path_bytes).decode("utf-16-le").rstrip("\x00")
    except (UnicodeDecodeError, ValueError):
        path_str = "<unreadable path>"

    access_names = {
        0x0001: "read",
        0x0002: "write",
        0x0004: "delete",
        0x0008: "execute",
        0x0010: "network",
    }
    access_str = access_names.get(access_type, f"access_type=0x{access_type:04x}")

    return (
        f"Sandbox violation: {access_str} denied on '{path_str}' "
        f"(pid={pid}, {violation_count} total violations)"
    )


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
# Sandbox runner launch (replaces DLL injection)
# ═══════════════════════════════════════════════════════════════════════════════


def _launch_runner_process_sync(
    cmd: str,
    cwd: str,
    session_id: str,
    env_vars: Optional[Dict[str, str]],
    timeout_ms: int,
) -> Tuple[int, str, str, bool]:
    """Launch the sandbox runner process with the target command.

    The runner installs inline hooks in its own process and then executes
    the target command as a subprocess. No DLL injection needed.

    Returns:
        (exit_code, stdout, stderr, timed_out)
    """
    # 1. Create pipes
    stdout_rd, stdout_wr = _create_pipes()
    stderr_rd, stderr_wr = _create_pipes()

    try:
        # 2. Build environment (inject session ID for runner to find shm)
        merged = dict(os.environ)
        if env_vars:
            merged.update(env_vars)
        merged[SANDBOX_ENV_VAR] = session_id
        # Enable debug logging in runner if parent has DEBUG level
        if logger.isEnabledFor(logging.DEBUG):
            merged["QWENPAW_HOOK_DEBUG"] = "1"
        pairs = [f"{k}={v}" for k, v in merged.items()]
        block_str = "\0".join(pairs) + "\0\0"
        env_block = ctypes.create_unicode_buffer(block_str)

        # 3. Build runner command line
        # The runner is invoked as: python -m module session_id b64_cmd [cwd]
        python_exe = sys.executable
        runner_module = "qwenpaw.sandbox.windows_ctypes_hook.sandbox_runner"
        b64_cmd = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
        cmd_line = f'"{python_exe}" -m {runner_module} {session_id} {b64_cmd}'
        if cwd:
            b64_cwd = base64.b64encode(cwd.encode("utf-8")).decode("ascii")
            cmd_line += f" {b64_cwd}"

        # 4. Fill STARTUPINFOW
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = STARTF_USESTDHANDLES
        si.hStdInput = _kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        si.hStdOutput = stdout_wr
        si.hStdError = stderr_wr

        # 5. CreateProcessW (NOT suspended — hooks install within runner)
        pi = PROCESS_INFORMATION()
        creation_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT

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

        # 6. Close child-side write handles
        _kernel32.CloseHandle(stdout_wr)
        stdout_wr = None
        _kernel32.CloseHandle(stderr_wr)
        stderr_wr = None

        # 7. Wait for process
        wait_result = _kernel32.WaitForSingleObject(pi.hProcess, timeout_ms)
        timed_out = wait_result == WAIT_TIMEOUT
        if timed_out:
            _kernel32.TerminateProcess(pi.hProcess, 1)

        # 8. Read pipe output
        stdout_data = _read_pipe(stdout_rd)
        stderr_data = _read_pipe(stderr_rd)

        # 9. Get exit code
        exit_code = ctypes.c_uint32()
        _kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))

        # 10. Cleanup handles
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
    """Windows sandbox using pure Python ctypes inline API hooking.

    No DLL compilation required. Policy is communicated via shared memory.
    The sandbox runner hooks NT APIs in its own process to enforce rules.

    Lifecycle: per-tool-call (create shared memory, execute, cleanup).
    """

    def __init__(self, config: SandboxConfig):
        self._config = config
        self._process = None
        self._session_id: str = ""
        self._shm_handle: Optional[ctypes.c_void_p] = None
        self._shm_view: Optional[ctypes.c_void_p] = None
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

        # Generate unique session ID
        self._session_id = secrets.token_hex(12)

        # Compile policy
        policy_bytes = _compile_policy(self._config, self._session_id)

        # Create shared memory
        self._shm_handle, self._shm_view = _create_shared_memory(
            self._session_id, policy_bytes
        )

        self._initialized = True
        logger.info(
            "WindowsHookSandbox initialized: session=%s (pure Python hooks)",
            self._session_id,
        )

    async def __aenter__(self):
        await self._initialize()
        return self

    async def execute(
        self,
        cmd: str,
        cwd: Optional[str] = None,
    ) -> ExecutionResult:
        start = time.monotonic()
        try:
            await self._initialize()
            cwd = cwd or self._config.workspace_dir
            timeout_ms = self._config.timeout_seconds * 1000

            loop = asyncio.get_event_loop()
            exit_code, stdout, stderr, timed_out = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    _launch_runner_process_sync,
                    cmd,
                    cwd,
                    self._session_id,
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
        if self._shm_view:
            _kernel32.UnmapViewOfFile(self._shm_view)
            self._shm_view = None
        if self._shm_handle:
            _kernel32.CloseHandle(self._shm_handle)
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
        - available: True if platform is win32 and Python is 64-bit
        - reason: Human-readable description
    """
    if sys.platform != "win32":
        return False, "Not running on Windows"

    import struct as _struct
    if _struct.calcsize("P") * 8 != 64:
        return False, "Requires 64-bit Python (inline hooks are x64 only)"

    return True, (
        "Windows hook sandbox (pure Python ctypes): "
        "user-mode NT API inline hooking, no DLL or ACL required."
    )
