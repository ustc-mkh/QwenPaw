# -*- coding: utf-8 -*-
"""Windows sandbox — AppContainer kernel-level process isolation.

Uses Windows AppContainer (Win8+) for kernel-level sandbox isolation:

  - **Process isolation**: AppContainer SID + named object namespace isolation.
    Each sandbox instance creates an ephemeral AppContainer profile.
    The sandboxed process runs inside the AppContainer, with kernel-enforced
    isolation of named objects (mutexes, pipes, events, shared memory).

  - **Filesystem isolation**: default-deny + explicit ACL grants.
    AppContainer processes cannot access any filesystem path by default.
    Workspace and mount paths are granted access via NTFS ACL entries
    for the AppContainer SID. deny_paths are excluded when building
    allow rules (allow-list model).

  - **Network isolation**: AppContainer Capability SIDs.
    Network access is controlled by granting/withholding well-known
    capability SIDs (internetClient, internetClientServer, etc.).
    No Windows Firewall rules needed.

  - **Registry isolation**: virtualized hive.
    AppContainer processes get a virtualized registry view.

Architecture:
    1. Create an ephemeral AppContainer profile (userenv.dll)
    2. Configure NTFS ACLs: grant AppContainer SID access to allowed paths
       (skipping deny_paths)
    3. Create stdout/stderr pipes with ACLs allowing AppContainer SID to write
    4. Launch process via CreateProcessW + STARTUPINFOEX with
       PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
    5. Wait for completion, read pipe output
    6. Cleanup: remove ACLs, delete AppContainer profile

Requirements:
    - Windows 8 / Server 2012 or later (AppContainer support)
    - Does NOT require Administrator privileges
    - Does NOT require creating a Windows user account
"""

import asyncio
import base64
import ctypes
import glob
import json
import logging
import os
import secrets
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from .config import ExecutionResult, SandboxConfig
from .local_sandbox import LocalSandbox

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Win32 constants
# ═══════════════════════════════════════════════════════════════════════════════

# CreateProcess flags
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400

# STARTUPINFO flags
STARTF_USESTDHANDLES = 0x00000100

# Process thread attribute
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

# WaitForSingleObject return values
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# Handle flags
HANDLE_FLAG_INHERIT = 0x00000001

# Security information flags
DACL_SECURITY_INFORMATION = 0x00000004

# ACL entry modes
GRANT_ACCESS = 1
NO_INHERITANCE = 0
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2

# Trustee form
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0

# Generic access rights
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

# AppContainer well-known capability SID strings
CAPABILITY_INTERNET_CLIENT = "S-1-15-3-1"
CAPABILITY_INTERNET_CLIENT_SERVER = "S-1-15-3-2"

# HRESULT for "already exists"
_HRESULT_ALREADY_EXISTS = (
    0x800700B7  # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
)

# AppContainer profile name prefix
_AC_PROFILE_PREFIX = "QwenPaw.Sandbox"

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


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", ctypes.c_uint32),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),  # PSID_AND_ATTRIBUTES
        ("CapabilityCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class TRUSTEE_W(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", ctypes.c_uint32),
        ("TrusteeForm", ctypes.c_uint32),
        ("TrusteeType", ctypes.c_uint32),
        ("ptstrName", ctypes.c_void_p),
    ]


class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", ctypes.c_uint32),
        ("grfAccessMode", ctypes.c_uint32),
        ("grfInheritance", ctypes.c_uint32),
        ("Trustee", TRUSTEE_W),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Win32 DLL function declarations (lazy load)
# ═══════════════════════════════════════════════════════════════════════════════

_kernel32 = None
_userenv = None
_advapi32 = None

# Type aliases for concise signature table
_VP = ctypes.c_void_p
_U32 = ctypes.c_uint32
_I32 = ctypes.c_int32
_SZ = ctypes.c_size_t
_WP = ctypes.c_wchar_p
_PVP = ctypes.POINTER(ctypes.c_void_p)
_PU32 = ctypes.POINTER(ctypes.c_uint32)
_PSZ = ctypes.POINTER(ctypes.c_size_t)
_PSA = ctypes.POINTER(SECURITY_ATTRIBUTES)
_PPI = ctypes.POINTER(PROCESS_INFORMATION)

# (argtypes, restype) for each DLL function
_DLL_SIGNATURES = {
    "kernel32": {
        "CreatePipe": ([_PVP, _PVP, _PSA, _U32], _I32),
        "SetHandleInformation": ([_VP, _U32, _U32], _I32),
        "InitializeProcThreadAttributeList": ([_VP, _U32, _U32, _PSZ], _I32),
        "UpdateProcThreadAttribute": (
            [_VP, _U32, _SZ, _VP, _SZ, _VP, _VP],
            _I32,
        ),
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
        "DeleteProcThreadAttributeList": ([_VP], None),
        "LocalFree": ([_VP], _VP),
        "GetLogicalDrives": ([], _U32),
    },
    "userenv": {
        "CreateAppContainerProfile": ([_WP, _WP, _WP, _VP, _U32, _PVP], _I32),
        "DeleteAppContainerProfile": ([_WP], _I32),
        "DeriveAppContainerSidFromAppContainerName": ([_WP, _PVP], _I32),
    },
    "advapi32": {
        "ConvertStringSidToSidW": ([_WP, _PVP], _I32),
        "ConvertSidToStringSidW": ([_VP, _PVP], _I32),
        "SetEntriesInAclW": ([_U32, _VP, _VP, _PVP], _U32),
        "InitializeSecurityDescriptor": ([_VP, _U32], _I32),
        "SetSecurityDescriptorDacl": ([_VP, _I32, _VP, _I32], _I32),
    },
}


def _load_dlls():
    """Lazy-load Win32 DLLs and configure function signatures.

    Only executed on Windows on first call.
    """
    global _kernel32, _userenv, _advapi32
    if _kernel32 is not None:
        return

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _userenv = ctypes.WinDLL("userenv", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    dlls = {"kernel32": _kernel32, "userenv": _userenv, "advapi32": _advapi32}
    for dll_name, funcs in _DLL_SIGNATURES.items():
        dll = dlls[dll_name]
        for func_name, (argtypes, restype) in funcs.items():
            fn = getattr(dll, func_name)
            fn.argtypes = argtypes
            fn.restype = restype


# ═══════════════════════════════════════════════════════════════════════════════
# Cached encoding values (constant per process lifetime)
# ═══════════════════════════════════════════════════════════════════════════════

_cached_oem_encoding: Optional[str] = None
_cached_ansi_encoding: Optional[str] = None


def _get_system_ansi_encoding() -> str:
    """Return the codec name for the system ANSI code page (e.g. 'cp936').

    Falls back to 'utf-8' if the code page cannot be determined.
    Result is cached after first call.
    """
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
    """Return the codec name for the system OEM code page (e.g. 'cp936').

    PowerShell writes to redirected pipes using the OEM code page by default
    ([Console]::OutputEncoding defaults to GetOEMCP). Falls back to the ANSI
    code page if the OEM page cannot be determined.
    Result is cached after first call.
    """
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
# AppContainer profile management
# ═══════════════════════════════════════════════════════════════════════════════


def _generate_profile_name() -> str:
    """Generate a unique AppContainer profile name."""
    return f"{_AC_PROFILE_PREFIX}.{secrets.token_hex(8)}"


def _string_sid_to_psid(sid_string: str) -> ctypes.c_void_p:
    """Convert a SID string (e.g. "S-1-15-3-1") to a PSID pointer.

    Caller must ensure _load_dlls() has been called.
    """
    psid = ctypes.c_void_p()
    ok = _advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(psid))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return psid


def _resolve_capability_sids(
    network_allow: List[str],
) -> Tuple[Optional[ctypes.Array], int]:
    """Return a SID_AND_ATTRIBUTES array based on network_allow config.

    Mapping rules:
      - ["*"]        -> internetClient + internetClientServer (allow all)
      - has domains  -> internetClient only
                        (AppContainer cannot filter by domain)
      - []           -> no capability (network fully isolated)
    """
    cap_sids: List[str] = []
    if network_allow:
        if "*" in network_allow:
            cap_sids.append(CAPABILITY_INTERNET_CLIENT)
            cap_sids.append(CAPABILITY_INTERNET_CLIENT_SERVER)
        else:
            cap_sids.append(CAPABILITY_INTERNET_CLIENT)
            logger.warning(
                "WindowsNativeSandbox: domain-level network filtering not"
                "supported by AppContainer. Granting general internetClient"
                " capability.",
            )

    if not cap_sids:
        return None, 0

    SE_GROUP_ENABLED = 0x00000004
    arr = (SID_AND_ATTRIBUTES * len(cap_sids))()
    psid_refs: List[ctypes.c_void_p] = []
    for i, sid_str in enumerate(cap_sids):
        psid = _string_sid_to_psid(sid_str)
        psid_refs.append(psid)
        arr[i].Sid = psid
        arr[i].Attributes = SE_GROUP_ENABLED
    setattr(arr, "psid_refs", psid_refs)
    return arr, len(cap_sids)


def create_appcontainer_profile(
    profile_name: str,
    cap_array: Optional[ctypes.Array],
    cap_count: int,
) -> ctypes.c_void_p:
    """Create an AppContainer profile, return the AppContainer SID pointer.

    If the profile already exists (crash residue), delete and recreate.
    Caller must ensure _load_dlls() has been called.
    """
    ac_sid = ctypes.c_void_p()
    hr = _userenv.CreateAppContainerProfile(
        profile_name,
        profile_name,
        "QwenPaw sandbox instance",
        ctypes.cast(cap_array, ctypes.c_void_p) if cap_array else None,
        cap_count,
        ctypes.byref(ac_sid),
    )
    if hr == ctypes.c_int32(_HRESULT_ALREADY_EXISTS).value:
        _userenv.DeleteAppContainerProfile(profile_name)
        hr = _userenv.CreateAppContainerProfile(
            profile_name,
            profile_name,
            "QwenPaw sandbox instance",
            ctypes.cast(cap_array, ctypes.c_void_p) if cap_array else None,
            cap_count,
            ctypes.byref(ac_sid),
        )
    if hr != 0:
        raise OSError(
            "CreateAppContainerProfile failed:"
            f"HRESULT=0x{hr & 0xFFFFFFFF:08X}",
        )
    logger.info("Created AppContainer profile '%s'", profile_name)
    return ac_sid


def delete_appcontainer_profile(profile_name: str) -> None:
    """Delete an AppContainer profile. Best-effort.

    Caller must ensure _load_dlls() has been called.
    """
    hr = _userenv.DeleteAppContainerProfile(profile_name)
    if hr == 0:
        logger.info("Deleted AppContainer profile '%s'", profile_name)
    else:
        logger.warning(
            "Failed to delete AppContainer profile '%s': HRESULT=0x%08X",
            profile_name,
            hr & 0xFFFFFFFF,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# NTFS ACL management
# ═══════════════════════════════════════════════════════════════════════════════


def _enumerate_drive_roots() -> List[str]:
    """Return existing drive root paths (e.g. ["C:\\\\", "D:\\\\"]).

    Uses GetLogicalDrives() bitmask for efficient enumeration.
    Caller must ensure _load_dlls() has been called.
    """
    bitmask = _kernel32.GetLogicalDrives()
    roots: List[str] = []
    for i in range(26):
        if bitmask & (1 << i):
            roots.append(f"{chr(65 + i)}:\\")
    return roots


def _expand_deny_paths(deny_paths: List[str]) -> List[str]:
    """Expand user-relative deny paths."""
    return [
        os.path.expanduser(path) if path.startswith("~") else path
        for path in deny_paths
    ]


def _windows_system_read_paths() -> List[str]:
    """Return Windows system paths that should always be readable.

    Only top-level directories are returned since icacls grants are
    inheritable (OI)(CI), making sub-path grants redundant.
    """
    windir = os.environ.get("SystemRoot", "C:\\Windows")
    progfiles = os.environ.get("ProgramFiles", "C:\\Program Files")
    progfiles86 = os.environ.get(
        "ProgramFiles(x86)",
        "C:\\Program Files (x86)",
    )

    paths = [
        windir,  # C:\Windows (includes System32, SysWOW64 via inheritance)
        progfiles,  # Installed programs
        progfiles86,  # 32-bit installed programs
    ]
    return [p for p in paths if os.path.isdir(p)]


def _build_acl_rules(
    config: SandboxConfig,
) -> Tuple[List[Tuple[str, str]], List[str], List[str]]:
    """Build ACL rules based on SandboxConfig.

    Strategy (aligned with Linux Landlock sandbox):
      1. Always grant system paths ReadAndExecute (PowerShell/cmd.exe need
         these regardless of allow_read_all setting).
      2. Always grant workspace_dir at least ReadAndExecute (it's the cwd for
         the sandboxed process). If a mount declares workspace_dir as
         writable, the workspace is granted FullControl directly
         (no double-grant).
      3. allow_read_all=True → additionally grant all drive roots
         inheritable ReadAndExecute (broad filesystem access).
      4. allow_read_all=False (strict mode) → only system paths + workspace +
         declared mounts are accessible.
      5. Mounts → grant per mount (FullControl if writable, ReadAndExecute
         otherwise). For read-only mounts, also apply deny-write ACE.
      6. deny_paths → apply explicit Deny ACE (with inheritance) to block
         the AppContainer SID from accessing the path and its children.

    Returns:
        (grant_rules, deny_full_paths, deny_write_paths) where:
          - grant_rules: [(path, access_level), ...] paths to grant
          - deny_full_paths: [path, ...] paths to apply full Deny ACE on
          - deny_write_paths: [path, ...] paths to apply write-deny ACE on
    """
    grant_rules: List[Tuple[str, str]] = []
    deny_expanded = _expand_deny_paths(config.deny_paths)
    deny_write_paths: List[str] = []
    # Track paths already granted (normcased) -> access level
    granted: Dict[str, str] = {}

    def _add_grant(path: str, level: str) -> None:
        """Add a grant rule, upgrading level if path already granted
        at lower."""
        norm = os.path.normcase(path)
        existing = granted.get(norm)
        if existing == "FullControl":
            return  # Already at max
        if existing == level:
            return  # Already granted at same level
        # FullControl upgrades anything; otherwise skip if already present
        if level == "FullControl" and existing:
            # Replace existing entry
            for i, (p, _) in enumerate(grant_rules):
                if os.path.normcase(p) == norm:
                    grant_rules[i] = (path, level)
                    break
            granted[norm] = level
        elif existing is None:
            grant_rules.append((path, level))
            granted[norm] = level

    # 1. System paths: always grant read+exec
    for sp in _windows_system_read_paths():
        _add_grant(sp, "ReadAndExecute")

    # 2. Determine workspace access level (check mounts first)
    ws = config.workspace_dir
    ws_level = "ReadAndExecute"
    if ws:
        for mount in config.mounts:
            if (
                os.path.normcase(mount.path) == os.path.normcase(ws)
                and mount.writable
            ):
                ws_level = "FullControl"
                break
        if os.path.exists(ws):
            _add_grant(ws, ws_level)

    # 3. allow_read_all: grant all drive roots with inheritable read
    if config.allow_read_all:
        for root in _enumerate_drive_roots():
            _add_grant(root, "ReadAndExecute")

    # 4. Mounts
    for mount in config.mounts:
        if not os.path.exists(mount.path):
            continue
        if mount.writable:
            _add_grant(mount.path, "FullControl")
        else:
            _add_grant(mount.path, "ReadAndExecute")
            deny_write_paths.append(mount.path)

    # 5. Deny paths
    return grant_rules, deny_expanded, deny_write_paths


def _psid_to_string(sid: ctypes.c_void_p) -> str:
    """Convert a PSID pointer to its string representation (e.g. S-1-15-2-...).

    Caller must ensure _load_dlls() has been called.
    """
    str_ptr = ctypes.c_void_p()
    ok = _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(str_ptr))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(str_ptr)
    finally:
        _kernel32.LocalFree(str_ptr)


def _icacls_grant(path: str, sid_string: str, access_level: str) -> None:
    """Grant an inheritable Allow ACE for a SID on a filesystem path
    using icacls.

    Args:
        path: Filesystem path to modify.
        sid_string: SID string (e.g. "S-1-15-2-...").
        access_level: "FullControl", "Modify", or "ReadAndExecute".
    """
    if access_level == "FullControl":
        perm = f"*{sid_string}:(OI)(CI)F"
    elif access_level == "Modify":
        perm = f"*{sid_string}:(OI)(CI)M"
    else:
        perm = f"*{sid_string}:(OI)(CI)RX"

    result = subprocess.run(
        ["icacls", path, "/grant", perm, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise OSError(
            f"icacls /grant failed on {path!r}: {result.stderr.strip()}",
        )


def _icacls_deny(path: str, sid_string: str) -> None:
    """Apply an inheritable Deny ACE for a SID on a filesystem path
    using icacls.

    Args:
        path: Filesystem path to deny access to.
        sid_string: SID string (e.g. "S-1-15-2-...").
    """
    perm = f"*{sid_string}:(OI)(CI)F"
    result = subprocess.run(
        ["icacls", path, "/deny", perm, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise OSError(
            f"icacls /deny failed on {path!r}: {result.stderr.strip()}",
        )


def _icacls_deny_write(path: str, sid_string: str) -> None:
    """Apply an inheritable Deny ACE for write/delete operations only.

    Used for read-only mounts: the SID can still read, but cannot write,
    append, delete, or modify.

    Args:
        path: Filesystem path to deny write access to.
        sid_string: SID string (e.g. "S-1-15-2-...").
    """
    perm = f"*{sid_string}:(OI)(CI)(WD,AD,WEA,WA,DE,DC)"
    result = subprocess.run(
        ["icacls", path, "/deny", perm, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise OSError(
            "icacls /deny (write) "
            f"failed on {path!r}: {result.stderr.strip()}",
        )


def _icacls_remove(path: str, sid_string: str) -> None:
    """Remove all ACEs (grant + deny) for a SID from a filesystem path.

    Uses a single icacls invocation with both /remove and /remove:d to
    remove grant and deny ACEs in one subprocess call.

    Args:
        path: Filesystem path to modify.
        sid_string: SID string (e.g. "S-1-15-2-...").
    """
    sid_ref = f"*{sid_string}"
    result = subprocess.run(
        ["icacls", path, "/remove", sid_ref, "/remove:d", sid_ref, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise OSError(
            f"icacls /remove failed on {path!r}: {result.stderr.strip()}",
        )


def _icacls_batch_grant(
    paths_and_levels: List[Tuple[str, str]],
    sid_string: str,
) -> List[str]:
    """Batch grant ACEs for multiple paths, returning successfully
    modified paths.

    Groups paths by access level and issues one icacls call per group.
    """
    by_level: Dict[str, List[str]] = {}
    for path, level in paths_and_levels:
        by_level.setdefault(level, []).append(path)

    modified: List[str] = []
    for level, paths in by_level.items():
        if level == "FullControl":
            perm_suffix = "(OI)(CI)F"
        elif level == "Modify":
            perm_suffix = "(OI)(CI)M"
        else:
            perm_suffix = "(OI)(CI)RX"

        perm = f"*{sid_string}:{perm_suffix}"
        # icacls supports multiple paths in one invocation
        cmd = ["icacls"] + paths + ["/grant", perm, "/C"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        if result.returncode == 0:
            modified.extend(paths)
        else:
            # Fallback: try individually for paths that may have failed
            for path in paths:
                try:
                    _icacls_grant(path, sid_string, level)
                    modified.append(path)
                except OSError as exc:
                    logger.warning("Failed to grant ACL for %s: %s", path, exc)
    return modified


def _icacls_batch_deny(paths: List[str], sid_string: str) -> List[str]:
    """Batch deny ACEs for multiple paths, returning successfully
    modified paths."""
    if not paths:
        return []
    perm = f"*{sid_string}:(OI)(CI)F"
    cmd = ["icacls"] + paths + ["/deny", perm, "/C"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    if result.returncode == 0:
        return list(paths)

    # Fallback: try individually
    modified: List[str] = []
    for path in paths:
        try:
            _icacls_deny(path, sid_string)
            modified.append(path)
        except OSError as exc:
            logger.warning("Failed to deny ACL for %s: %s", path, exc)
    return modified


def _icacls_batch_deny_write(paths: List[str], sid_string: str) -> List[str]:
    """Batch deny-write ACEs for multiple paths."""
    if not paths:
        return []
    perm = f"*{sid_string}:(OI)(CI)(WD,AD,WEA,WA,DE,DC)"
    cmd = ["icacls"] + paths + ["/deny", perm, "/C"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    if result.returncode == 0:
        return list(paths)

    # Fallback: try individually
    modified: List[str] = []
    for path in paths:
        try:
            _icacls_deny_write(path, sid_string)
            modified.append(path)
        except OSError as exc:
            logger.warning("Failed to deny-write ACL for %s: %s", path, exc)
    return modified


def _icacls_batch_remove(paths: List[str], sid_string: str) -> None:
    """Batch remove all ACEs for a SID from multiple paths."""
    if not paths:
        return
    sid_ref = f"*{sid_string}"
    cmd = ["icacls"] + paths + ["/remove", sid_ref, "/remove:d", sid_ref, "/C"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    if result.returncode != 0:
        # Fallback: try individually (best-effort)
        for path in paths:
            try:
                _icacls_remove(path, sid_string)
            except OSError as exc:
                logger.debug("Failed to clean up ACL for %s: %s", path, exc)


def configure_acls(
    config: SandboxConfig,
    ac_sid: ctypes.c_void_p,
) -> List[str]:
    """Configure NTFS ACLs for the AppContainer SID using icacls.

    Strategy:
      1. Grant allowed paths (drive roots or mounts)
      2. Deny-write on read-only mounts (explicit Deny ACE for write ops)
      3. Full deny on deny_paths (explicit Deny ACE overrides inherited Allow)

    Args:
        config: Sandbox configuration with path/mount declarations.
        ac_sid: PSID pointer for the AppContainer (caller retains ownership).

    Returns:
        List of paths where ACEs were modified (for cleanup).

    Caller must ensure _load_dlls() has been called.
    """
    sid_string = _psid_to_string(ac_sid)
    (
        grant_rules,
        deny_full_paths,
        deny_write_paths,
    ) = _build_acl_rules(config)
    modified_paths: List[str] = []

    # 1. Batch grant rules
    existing_grants = [
        (path, level) for path, level in grant_rules if os.path.exists(path)
    ]
    modified_paths.extend(_icacls_batch_grant(existing_grants, sid_string))

    # 2. Batch deny-write rules (read-only mounts)
    existing_deny_write = [p for p in deny_write_paths if os.path.exists(p)]
    modified_paths.extend(
        _icacls_batch_deny_write(existing_deny_write, sid_string),
    )

    # 3. Batch full deny rules (deny_paths)
    existing_deny_full = [p for p in deny_full_paths if os.path.exists(p)]
    modified_paths.extend(_icacls_batch_deny(existing_deny_full, sid_string))

    return modified_paths


def cleanup_acls(
    granted_paths: List[str],
    ac_sid: ctypes.c_void_p,
) -> None:
    """Remove all ACL entries added for the AppContainer SID.

    Best-effort batch removal of both grant and deny ACEs.

    Args:
        granted_paths: Paths previously returned by configure_acls.
        ac_sid: PSID pointer for the AppContainer (caller retains ownership).

    Caller must ensure _load_dlls() has been called.
    """
    sid_string = _psid_to_string(ac_sid)
    existing = [p for p in granted_paths if os.path.exists(p)]
    _icacls_batch_remove(existing, sid_string)


# ═══════════════════════════════════════════════════════════════════════════════
# Session log for crash recovery
# ═══════════════════════════════════════════════════════════════════════════════

# Session logs are per-sandbox JSON files stored in .sandbox_logs/ next to this
# module. Each file records the PID, profile name, SID, and modified ACL paths
# so that stale sandboxes (from crashed processes) can be fully cleaned up on
# next startup.
_LOG_DIR_NAME = ".sandbox_logs"

# Cached log directory path (resolved once per process).
_log_dir_cache: Optional[str] = None

# Module-level flag: stale cleanup runs at most once per process.
_stale_cleanup_done = False


def _log_dir() -> str:
    """Return the directory used for sandbox session logs, creating if needed.

    Primary: <this_module_dir>/.sandbox_logs/
    Fallback: %LOCALAPPDATA%/qwenpaw/.sandbox_logs/
              (if source dir is read-only)
    """
    global _log_dir_cache  # noqa: PLW0603
    if _log_dir_cache is not None:
        return _log_dir_cache

    # Primary: next to this source file
    module_dir = os.path.dirname(os.path.abspath(__file__))
    primary = os.path.join(module_dir, _LOG_DIR_NAME)
    try:
        os.makedirs(primary, exist_ok=True)
        # Verify writability
        test_file = os.path.join(primary, ".write_test")
        with open(test_file, "w") as f:
            f.write("")
        os.unlink(test_file)
        _log_dir_cache = primary
        return primary
    except OSError:
        pass

    # Fallback: user data directory
    base = (
        os.environ.get("LOCALAPPDATA")
        or os.environ.get("TEMP")
        or os.environ.get("TMP")
        or os.path.expanduser("~")
    )
    fallback = os.path.join(base, "qwenpaw", _LOG_DIR_NAME)
    os.makedirs(fallback, exist_ok=True)
    _log_dir_cache = fallback
    return fallback


def _log_file_path(profile_name: str) -> str:
    """Return the session log file path for a given profile name."""
    return os.path.join(_log_dir(), f"{profile_name}.json")


def _write_session_log(
    profile_name: str,
    sid_string: str,
    granted_paths: List[str],
) -> None:
    """Atomically write a session log file for crash recovery."""
    import datetime
    import tempfile

    path = _log_file_path(profile_name)
    data = {
        "pid": os.getpid(),
        "profile_name": profile_name,
        "sid_string": sid_string,
        "granted_paths": granted_paths,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    try:
        dir_path = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except BaseException:
            os.unlink(tmp_path)
            raise
        os.replace(tmp_path, path)
    except OSError as exc:
        logger.debug("Failed to write session log %s: %s", path, exc)


def _remove_session_log(profile_name: str) -> None:
    """Remove the session log file for a given profile name."""
    path = _log_file_path(profile_name)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("Failed to remove session log %s: %s", path, exc)


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running (Windows)."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259  # 0x103
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
        if not handle:
            return False
        try:
            exit_code = ctypes.c_uint32()
            if kernel32.GetExitCodeProcess(
                handle,
                ctypes.byref(exit_code),
            ):
                return exit_code.value == STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(handle)
    except (OSError, AttributeError):
        return False


def _cleanup_stale_sandboxes() -> None:
    """Scan session logs for crashed sandbox instances and clean up.

    For each session log file:
      1. Check if the owning PID is still alive — if yes, skip.
      2. If the PID is dead, use the stored SID string to remove ACEs.
      3. Delete the orphaned AppContainer profile.
      4. Remove the session log file.

    Runs at most once per process (guarded by _stale_cleanup_done flag).
    """
    global _stale_cleanup_done
    if _stale_cleanup_done:
        return
    _stale_cleanup_done = True

    try:
        log_d = _log_dir()
    except OSError:
        return

    pattern = os.path.join(log_d, f"{_AC_PROFILE_PREFIX}.*.json")
    for log_path in glob.glob(pattern):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, ValueError):
            try:
                os.unlink(log_path)
            except OSError:
                pass
            continue

        pid = data.get("pid", -1)
        profile_name = data.get("profile_name", "")
        sid_string = data.get("sid_string", "")
        granted_paths = data.get("granted_paths", [])

        if not profile_name:
            try:
                os.unlink(log_path)
            except OSError:
                pass
            continue

        # Skip if the owning process is still alive
        if isinstance(pid, int) and pid > 0 and _is_pid_alive(pid):
            continue

        # Stale entry: clean up
        logger.info(
            "Cleaning up stale sandbox '%s' (pid=%s no longer alive)",
            profile_name,
            pid,
        )

        # Remove ACEs from recorded paths
        if sid_string and granted_paths:
            existing = [p for p in granted_paths if os.path.exists(p)]
            if existing:
                _icacls_batch_remove(existing, sid_string)
        elif granted_paths:
            # Fallback: derive SID from profile name
            try:
                ac_sid = ctypes.c_void_p()
                hr = _userenv.DeriveAppContainerSidFromAppContainerName(
                    profile_name,
                    ctypes.byref(ac_sid),
                )
                if hr == 0:
                    derived_sid = _psid_to_string(ac_sid)
                    existing = [p for p in granted_paths if os.path.exists(p)]
                    if existing:
                        _icacls_batch_remove(existing, derived_sid)
                    _kernel32.LocalFree(ac_sid)
                else:
                    logger.debug(
                        "Cannot derive SID for stale profile '%s' "
                        "(HRESULT=0x%08X), skipping ACL cleanup",
                        profile_name,
                        hr & 0xFFFFFFFF,
                    )
            except Exception as exc:
                logger.debug(
                    "Error during stale ACL cleanup for '%s': %s",
                    profile_name,
                    exc,
                )

        # Delete the orphaned profile
        delete_appcontainer_profile(profile_name)

        # Remove the session log
        try:
            os.unlink(log_path)
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Pipe creation for AppContainer process
# ═══════════════════════════════════════════════════════════════════════════════


def _make_explicit_access(
    sid: ctypes.c_void_p,
    access_mask: int,
    inheritance: int,
) -> EXPLICIT_ACCESS_W:
    """Build an EXPLICIT_ACCESS_W structure for SetEntriesInAclW
    (pipe DACL)."""
    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = access_mask
    ea.grfAccessMode = GRANT_ACCESS
    ea.grfInheritance = inheritance
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = 0
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
    ea.Trustee.ptstrName = sid.value
    return ea


def _create_pipe_for_appcontainer(
    ac_sid: ctypes.c_void_p,
) -> Tuple[ctypes.c_void_p, ctypes.c_void_p]:
    """Create a pipe pair where the write end allows AppContainer SID to write.

    Returns (read_handle, write_handle).
    read_handle is non-inheritable (held by parent); write_handle is
    inheritable (child writes).

    Caller must ensure _load_dlls() has been called.
    """
    read_h = ctypes.c_void_p()
    write_h = ctypes.c_void_p()

    # Build a DACL that grants Everyone full control + AppContainer SID r/w.
    everyone_sid = _string_sid_to_psid("S-1-1-0")
    new_dacl = ctypes.c_void_p()
    try:
        ea_array = (EXPLICIT_ACCESS_W * 2)()
        # Entry 0: Everyone — full control (matches default pipe DACL)
        ea_array[0] = _make_explicit_access(
            everyone_sid,
            0x1F01FF,
            NO_INHERITANCE,  # FILE_ALL_ACCESS
        )
        # Entry 1: AppContainer SID — read + write
        ea_array[1] = _make_explicit_access(
            ac_sid,
            GENERIC_WRITE | GENERIC_READ,
            NO_INHERITANCE,
        )
        rc = _advapi32.SetEntriesInAclW(
            2,
            ctypes.cast(ea_array, ctypes.c_void_p),
            None,
            ctypes.byref(new_dacl),
        )
        if rc != 0:
            raise OSError(f"SetEntriesInAclW for pipe DACL failed: error={rc}")

        # Build a security descriptor with this DACL.
        SECURITY_DESCRIPTOR_REVISION = 1
        sd_buf = (ctypes.c_byte * 64)()
        if not _advapi32.InitializeSecurityDescriptor(
            ctypes.byref(sd_buf),
            SECURITY_DESCRIPTOR_REVISION,
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        if not _advapi32.SetSecurityDescriptorDacl(
            ctypes.byref(sd_buf),
            1,
            new_dacl,
            0,
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(sa)
        sa.bInheritHandle = 1
        sa.lpSecurityDescriptor = ctypes.addressof(sd_buf)

        ok = _kernel32.CreatePipe(
            ctypes.byref(read_h),
            ctypes.byref(write_h),
            ctypes.byref(sa),
            0,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if new_dacl:
            _kernel32.LocalFree(new_dacl)
        _kernel32.LocalFree(everyone_sid)

    # read end should not be inherited by child process
    _kernel32.SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0)

    return read_h, write_h


def _read_pipe(handle: ctypes.c_void_p) -> str:
    """Read all data from a pipe until EOF. Synchronous blocking call.

    Caller must ensure _load_dlls() has been called.

    Decoding strategy: OEM code page → ANSI code page → UTF-8 with replacement.
    """
    ERROR_BROKEN_PIPE = 109
    chunks: List[bytes] = []
    buf_size = 8192
    buf = (ctypes.c_ubyte * buf_size)()
    bytes_read = ctypes.c_uint32()
    while True:
        ok = _kernel32.ReadFile(
            handle,
            buf,
            buf_size,
            ctypes.byref(bytes_read),
            None,
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


def _build_powershell_command_line(cmd: str) -> str:
    """Build a PowerShell command line using -EncodedCommand.

    Wraps the user command in a script that:
      1. Suppresses progress bar output ($ProgressPreference)
      2. Executes the user command
      3. Propagates the exit code — uses $LASTEXITCODE for external programs,
         falls back to $? (cmdlet success indicator) when $LASTEXITCODE is null

    Returns a full command line string suitable for CreateProcessW.
    """
    script = (
        "$ProgressPreference = 'SilentlyContinue'\n"
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
    """Clean PowerShell CLIXML stderr output, preserving error messages.

    PowerShell writes ALL stderr as CLIXML when output is redirected to a pipe.
    This function extracts error text from <S S="Error">...</S> tags and
    strips progress records.
    """
    import re

    if not stderr:
        return stderr

    # Check if this is CLIXML format
    if "#< CLIXML" not in stderr:
        return stderr.strip()

    # Extract error messages from CLIXML <S S="Error">...</S> tags
    error_parts: List[str] = []
    for match in re.finditer(r'<S S="Error">(.*?)</S>', stderr, re.DOTALL):
        text = match.group(1)
        text = text.replace("_x000D__x000A_", "\n")
        text = text.replace("_x000D_", "\r")
        text = text.replace("_x000A_", "\n")
        error_parts.append(text)

    if error_parts:
        return "".join(error_parts).strip()

    # Fallback: strip CLIXML markers and XML tags
    cleaned = stderr
    cleaned = cleaned.replace("#< CLIXML", "")
    cleaned = re.sub(r"</?Objs[^>]*>", "", cleaned)
    cleaned = re.sub(r"<PR [^>]*/>", "", cleaned)
    cleaned = re.sub(r'<S S="[^"]*">', "", cleaned)
    cleaned = re.sub(r"</S>", "", cleaned)
    return cleaned.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# AppContainer process launch
# ═══════════════════════════════════════════════════════════════════════════════


def _build_env_block(
    env_vars: Optional[Dict[str, str]],
) -> Optional[ctypes.Array]:
    """Build a Unicode environment block (double-null-terminated)
    for CreateProcessW.

    If env_vars is empty, returns None (inherit parent environment).
    """
    if not env_vars:
        return None
    merged = dict(os.environ)
    merged.update(env_vars)
    pairs = [f"{k}={v}" for k, v in merged.items()]
    block_str = "\0".join(pairs) + "\0\0"
    return ctypes.create_unicode_buffer(block_str)


def _launch_in_appcontainer_sync(
    cmd: str,
    cwd: str,
    ac_sid: ctypes.c_void_p,
    cap_array: Optional[ctypes.Array],
    cap_count: int,
    env_vars: Optional[Dict[str, str]],
    timeout_ms: int,
) -> Tuple[int, str, str, bool]:
    """Launch a process inside AppContainer synchronously.

    Returns (exit_code, stdout, stderr, timed_out).
    This function runs in a thread pool executor, not blocking the event loop.

    Caller must ensure _load_dlls() has been called.
    """
    # 1. Create stdout/stderr pipes
    stdout_rd, stdout_wr = _create_pipe_for_appcontainer(ac_sid)
    stderr_rd, stderr_wr = _create_pipe_for_appcontainer(ac_sid)

    try:
        # 2. Build SECURITY_CAPABILITIES
        sec_cap = SECURITY_CAPABILITIES()
        sec_cap.AppContainerSid = ac_sid
        if cap_array is not None and cap_count > 0:
            sec_cap.Capabilities = ctypes.cast(cap_array, ctypes.c_void_p)
            sec_cap.CapabilityCount = cap_count
        else:
            sec_cap.Capabilities = None
            sec_cap.CapabilityCount = 0
        sec_cap.Reserved = 0

        # 3. Initialize ProcThreadAttributeList
        attr_size = ctypes.c_size_t(0)
        _kernel32.InitializeProcThreadAttributeList(
            None,
            1,
            0,
            ctypes.byref(attr_size),
        )
        attr_list_buf = (ctypes.c_byte * attr_size.value)()
        attr_list = ctypes.cast(attr_list_buf, ctypes.c_void_p)
        ok = _kernel32.InitializeProcThreadAttributeList(
            attr_list,
            1,
            0,
            ctypes.byref(attr_size),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

        # 4. Inject SECURITY_CAPABILITIES
        ok = _kernel32.UpdateProcThreadAttribute(
            attr_list,
            0,
            ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(sec_cap),
            ctypes.c_size_t(ctypes.sizeof(sec_cap)),
            None,
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

        # 5. Fill STARTUPINFOEXW
        si_ex = STARTUPINFOEXW()
        si_ex.StartupInfo.cb = ctypes.sizeof(si_ex)
        si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si_ex.StartupInfo.hStdInput = _kernel32.GetStdHandle(-10)
        si_ex.StartupInfo.hStdOutput = stdout_wr
        si_ex.StartupInfo.hStdError = stderr_wr
        si_ex.lpAttributeList = attr_list

        # 6. Build command line and environment block
        cmd_line = _build_powershell_command_line(cmd)
        env_block = _build_env_block(env_vars)
        creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
        if env_block is not None:
            creation_flags |= CREATE_UNICODE_ENVIRONMENT

        # 7. CreateProcessW
        pi = PROCESS_INFORMATION()
        ok = _kernel32.CreateProcessW(
            None,
            cmd_line,
            None,
            None,
            1,  # bInheritHandles = TRUE
            creation_flags,
            ctypes.cast(env_block, ctypes.c_void_p) if env_block else None,
            cwd,
            ctypes.byref(si_ex),
            ctypes.byref(pi),
        )
        if not ok:
            err = ctypes.get_last_error()
            _kernel32.DeleteProcThreadAttributeList(attr_list)
            raise OSError(
                f"CreateProcessW failed: error={err} "
                f"({ctypes.FormatError(err)})",
            )

        # 8. Close child-side write handles
        _kernel32.CloseHandle(stdout_wr)
        stdout_wr = None
        _kernel32.CloseHandle(stderr_wr)
        stderr_wr = None

        # 9. Wait for process to finish
        wait_result = _kernel32.WaitForSingleObject(pi.hProcess, timeout_ms)
        timed_out = wait_result == WAIT_TIMEOUT
        if timed_out:
            _kernel32.TerminateProcess(pi.hProcess, 1)

        # 10. Read pipe output
        stdout_data = _read_pipe(stdout_rd)
        stderr_data = _read_pipe(stderr_rd)

        # 11. Get exit code
        exit_code = ctypes.c_uint32()
        _kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))

        # 12. Cleanup handles
        _kernel32.CloseHandle(pi.hProcess)
        _kernel32.CloseHandle(pi.hThread)
        _kernel32.DeleteProcThreadAttributeList(attr_list)

        return (
            exit_code.value if not timed_out else -1,
            stdout_data,
            stderr_data,
            timed_out,
        )
    finally:
        # Ensure write handles are closed (if not already)
        if stdout_wr is not None:
            _kernel32.CloseHandle(stdout_wr)
        if stderr_wr is not None:
            _kernel32.CloseHandle(stderr_wr)
        _kernel32.CloseHandle(stdout_rd)
        _kernel32.CloseHandle(stderr_rd)


# ═══════════════════════════════════════════════════════════════════════════════
# WindowsNativeSandbox class
# ═══════════════════════════════════════════════════════════════════════════════


class WindowsNativeSandbox(LocalSandbox):
    """Native Windows sandbox using AppContainer process isolation.

    Deny-default allow-list model:
      - System paths covered by ALL APPLICATION PACKAGES pre-set ACE
        (read + exec)
      - %TEMP% writable
      - config.mounts granted per writable declaration
      - allow_read_all=True -> full disk readable (enumerate drive roots)
      - allow_read_all=True + deny_paths -> enumerate skipping deny_paths
      - allow_read_all=False -> strict mode, only system + mounts
      - Network controlled by AppContainer Capability SIDs

    Lifecycle: per-tool-call (create, execute, cleanup).
    """

    def __init__(self, config: SandboxConfig):
        self._config = config
        self._process = None  # unused; kept for base-class compatibility
        self._profile_name: str = ""
        self._ac_sid: Optional[ctypes.c_void_p] = None
        self._cap_array: Optional[ctypes.Array] = None
        self._cap_count: int = 0
        self._initialized = False
        self._granted_paths: List[str] = []

    async def _initialize(self) -> None:
        if self._initialized:
            return

        import sys

        if sys.platform != "win32":
            raise RuntimeError(
                "WindowsNativeSandbox requires Windows. "
                "Use SandboxMode.NONE for unisolated execution.",
            )

        # Load DLLs once — all downstream functions assume they are loaded.
        _load_dlls()

        # Best-effort cleanup of stale sandbox remnants (once per process).
        try:
            _cleanup_stale_sandboxes()
        except Exception as exc:
            logger.debug("Stale sandbox cleanup failed (non-fatal): %s", exc)

        # Resolve network capabilities
        self._cap_array, self._cap_count = _resolve_capability_sids(
            self._config.network_allow,
        )

        # Create AppContainer profile
        self._profile_name = _generate_profile_name()
        self._ac_sid = create_appcontainer_profile(
            self._profile_name,
            self._cap_array,
            self._cap_count,
        )

        # Configure filesystem ACLs
        self._granted_paths = configure_acls(
            config=self._config,
            ac_sid=self._ac_sid,
        )

        # Store SID string for session log
        self._sid_string = _psid_to_string(self._ac_sid)

        # Write session log for crash recovery
        _write_session_log(
            self._profile_name,
            self._sid_string,
            self._granted_paths,
        )

        self._initialized = True

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
                    _launch_in_appcontainer_sync,
                    cmd,
                    cwd,
                    self._ac_sid,
                    self._cap_array,
                    self._cap_count,
                    self._config.env_vars or None,
                    timeout_ms,
                ),
                timeout=self._config.timeout_seconds + 10,
            )
            duration_ms = int((time.monotonic() - start) * 1000)

            # Clean PowerShell CLIXML noise from stderr
            stderr = _clean_powershell_stderr(stderr)

            # Detect sandbox violation from stderr keywords
            violation = None
            if not timed_out and exit_code != 0:
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
        """No-op: AppContainer process lifetime is owned by the sync
        launcher."""
        return None

    async def cleanup(self) -> None:
        """Full cleanup: remove ACLs, delete AppContainer profile,
        remove session log."""
        granted_paths = list(self._granted_paths)
        ac_sid = self._ac_sid
        profile_name = self._profile_name

        if granted_paths and ac_sid:
            cleanup_acls(
                granted_paths=granted_paths,
                ac_sid=ac_sid,
            )

        if profile_name:
            delete_appcontainer_profile(profile_name)
            _remove_session_log(profile_name)

        self._profile_name = ""
        self._ac_sid = None
        self._granted_paths = []

    async def __aexit__(self, exc_type, exc, tb):
        await self.cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# Platform probe
# ═══════════════════════════════════════════════════════════════════════════════


def probe_windows_native() -> Tuple[bool, str]:
    """Probe native Windows sandbox capabilities (AppContainer).

    Returns:
        (available, reason)
        - available: True if AppContainer is available
            (Win8+, no admin required)
        - reason: Human-readable description
    """
    import sys

    if sys.platform != "win32":
        return False, "Not running on Windows"

    try:
        _load_dlls()
        test_name = f"{_AC_PROFILE_PREFIX}._probe_{secrets.token_hex(4)}"
        ac_sid = ctypes.c_void_p()
        hr = _userenv.CreateAppContainerProfile(
            test_name,
            test_name,
            "probe",
            None,
            0,
            ctypes.byref(ac_sid),
        )
        if hr == 0:
            _userenv.DeleteAppContainerProfile(test_name)
            return True, (
                "Native Windows sandbox (AppContainer): "
                "kernel-level process isolation, no admin required"
            )
        else:
            return False, (
                f"AppContainer not available: "
                f"CreateAppContainerProfile HRESULT=0x{hr & 0xFFFFFFFF:08X}"
            )
    except Exception as e:
        return False, f"AppContainer probe failed: {e}"
