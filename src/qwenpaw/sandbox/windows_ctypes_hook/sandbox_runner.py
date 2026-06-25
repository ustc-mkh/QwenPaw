# -*- coding: utf-8 -*-
"""Sandbox runner — the hooked child process entry point.

Launched by the parent (WindowsHookSandbox) as:
  python -m qwenpaw.sandbox.windows_ctypes_hook.sandbox_runner <session_id> <b64_cmd> [b64_cwd]

Lifecycle:
  1. Open shared memory (created by parent), read JSON policy
  2. Install inline hooks on NT APIs (NtCreateFile, NtOpenFile, NtDeleteFile)
  3. Install CreateProcessW/A hooks for recursive sandboxing of child processes
  4. Execute the target command via subprocess
  5. Pipe stdout/stderr back (parent reads from our stdout/stderr)
  6. Exit with the target's exit code

Recursive sandboxing:
  The CreateProcessW/A hooks intercept all child process creation. When a new
  process is being spawned, the hook rewrites it to launch through another
  sandbox_runner instance (sharing the same session_id / shared memory).
  Anti-recursion is achieved by:
    - Checking if the command line already contains our runner module name
    - Using env var QWENPAW_SANDBOX_SESSION to signal we're inside a sandbox
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import logging
import os
import struct
import subprocess
import sys
from typing import Optional

# Configure logging before imports that use it
logging.basicConfig(
    level=logging.DEBUG
    if os.environ.get("QWENPAW_HOOK_DEBUG")
    else logging.WARNING,
    format="[sandbox_runner %(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

from .hook_engine import HookManager  # noqa: E402
from .nt_api_types import (  # noqa: E402
    HANDLE,
    IO_STATUS_BLOCK,
    LARGE_INTEGER,
    NTSTATUS,
    OBJECT_ATTRIBUTES,
    STATUS_ACCESS_DENIED,
    UNICODE_STRING,
    CreateProcessA_t,
    CreateProcessW_t,
    NtCreateFile_t,
    NtDeleteFile_t,
    NtOpenFile_t,
)
from .policy_checker import PolicyChecker  # noqa: E402
from .shm_protocol import SharedMemoryReader  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

_ENV_SANDBOX_SESSION = "QWENPAW_SANDBOX_SESSION"
_RUNNER_MODULE = "qwenpaw.sandbox.windows_ctypes_hook.sandbox_runner"

# ═══════════════════════════════════════════════════════════════════════════════
# Global state (must be module-level for hook callbacks to access)
# ═══════════════════════════════════════════════════════════════════════════════

_policy: Optional[PolicyChecker] = None
_shm: Optional[SharedMemoryReader] = None
_hook_manager: Optional[HookManager] = None
_session_id: str = ""
_python_exe: str = ""
_runner_module: str = _RUNNER_MODULE
_is_child_runner: bool = (
    False  # True if this is a child sandbox_runner (level 1+)
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper: extract path from OBJECT_ATTRIBUTES
# ═══════════════════════════════════════════════════════════════════════════════


def _extract_path(obj_attr_ptr) -> Optional[str]:
    """Extract the file path string from an OBJECT_ATTRIBUTES pointer.

    Returns None if the pointer is null or the path cannot be read.
    """
    if not obj_attr_ptr:
        return None
    try:
        obj_attr = ctypes.cast(
            obj_attr_ptr,
            ctypes.POINTER(OBJECT_ATTRIBUTES),
        ).contents
        if not obj_attr.ObjectName:
            return None
        ustr = obj_attr.ObjectName.contents
        if not ustr.Buffer or ustr.Length == 0:
            return None
        # Length is in bytes; each WCHAR is 2 bytes
        char_count = ustr.Length // 2
        # Read the path from the UNICODE_STRING buffer
        return ustr.Buffer[:char_count]
    except (OSError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Hook callbacks
# ═══════════════════════════════════════════════════════════════════════════════


def _check_file_access(obj_attr_ptr, desired_access: int) -> Optional[int]:
    """Common check logic for NtCreateFile/NtOpenFile/NtDeleteFile.

    Returns STATUS_ACCESS_DENIED if blocked, None if allowed.
    """
    global _policy, _shm
    if not _policy:
        return None

    raw_path = _extract_path(obj_attr_ptr)
    if not raw_path:
        return None

    norm_path = _policy.normalize_nt_path(raw_path)
    if not norm_path:
        return None  # Cannot normalize → allow (e.g. \Device\... paths)

    allowed, vtype = _policy.check(norm_path, desired_access)
    if not allowed:
        logger.debug(
            "DENIED: %s (access=0x%08X, violation=%d)",
            norm_path,
            desired_access,
            vtype,
        )
        if _shm:
            _shm.log_violation(norm_path, vtype)
        return STATUS_ACCESS_DENIED
    return None


def _hooked_NtCreateFile(
    file_handle,
    desired_access,
    obj_attr,
    io_status,
    alloc_size,
    file_attrs,
    share_access,
    create_disp,
    create_opts,
    ea_buffer,
    ea_length,
):
    """Hook for ntdll!NtCreateFile."""
    try:
        result = _check_file_access(obj_attr, desired_access)
        if result is not None:
            return result
    except Exception as e:
        logger.debug("Exception in NtCreateFile hook: %s", e)

    # Call original
    original = _hook_manager.get_original("NtCreateFile", NtCreateFile_t)
    return original(
        file_handle,
        desired_access,
        obj_attr,
        io_status,
        alloc_size,
        file_attrs,
        share_access,
        create_disp,
        create_opts,
        ea_buffer,
        ea_length,
    )


def _hooked_NtOpenFile(
    file_handle,
    desired_access,
    obj_attr,
    io_status,
    share_access,
    open_options,
):
    """Hook for ntdll!NtOpenFile."""
    try:
        result = _check_file_access(obj_attr, desired_access)
        if result is not None:
            return result
    except Exception as e:
        logger.debug("Exception in NtOpenFile hook: %s", e)

    original = _hook_manager.get_original("NtOpenFile", NtOpenFile_t)
    return original(
        file_handle,
        desired_access,
        obj_attr,
        io_status,
        share_access,
        open_options,
    )


def _hooked_NtDeleteFile(obj_attr):
    """Hook for ntdll!NtDeleteFile."""
    try:
        # NtDeleteFile implies DELETE access
        result = _check_file_access(obj_attr, 0x00010000)  # DELETE
        if result is not None:
            return result
    except Exception as e:
        logger.debug("Exception in NtDeleteFile hook: %s", e)

    original = _hook_manager.get_original("NtDeleteFile", NtDeleteFile_t)
    return original(obj_attr)


def _is_already_sandboxed(cmd_line: str) -> bool:
    """Check if a command line is already a sandbox_runner invocation.

    This prevents infinite recursion: if the command being created is
    itself a sandbox_runner, we pass through without re-wrapping.
    """
    if not cmd_line:
        return False
    return _RUNNER_MODULE in cmd_line


def _build_wrapped_cmdline(original_cmd: str) -> str:
    """Build a new command line that runs through sandbox_runner.

    Returns a command line like:
      "<python_exe>" -m qwenpaw.sandbox.windows_ctypes_hook.sandbox_runner <session_id> <b64_cmd>
    """
    b64_cmd = base64.b64encode(original_cmd.encode("utf-8")).decode("ascii")
    return f'"{_python_exe}" -m {_RUNNER_MODULE} {_session_id} {b64_cmd}'


def _hooked_CreateProcessW(
    app_name,
    cmd_line,
    proc_attr,
    thread_attr,
    inherit_handles,
    creation_flags,
    environment,
    current_dir,
    startup_info,
    proc_info,
):
    """Hook for kernel32!CreateProcessW.

    Rewrites child process creation to go through another sandbox_runner
    instance, ensuring recursive sandboxing. Each child gets its own
    inline hooks protecting its NT API calls.

    Anti-recursion logic:
      - If _is_child_runner is True, this sandbox_runner was itself spawned
        by a parent sandbox_runner's CreateProcessW hook. In this case, we
        do NOT rewrap — the child's own NtCreateFile/NtOpenFile/NtDeleteFile
        hooks are sufficient to protect file I/O.
      - If the cmd_line already contains our module name, pass through.
    """
    original = _hook_manager.get_original("CreateProcessW", CreateProcessW_t)

    if cmd_line:
        logger.debug("CreateProcessW intercepted: %s", cmd_line[:200])

    # Anti-recursion: child runners don't rewrap (their NT hooks protect I/O)
    if _is_child_runner or not cmd_line or _is_already_sandboxed(cmd_line):
        return original(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )

    # Rewrap: launch child through sandbox_runner
    try:
        new_cmd = _build_wrapped_cmdline(cmd_line)
        logger.debug("CreateProcessW rewrapped: %s", new_cmd[:200])

        return original(
            None,  # app_name = None (use cmd_line)
            new_cmd,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )
    except Exception as e:
        logger.debug("CreateProcessW rewrap failed: %s, falling back", e)
        # Fallback: pass through original command
        return original(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )


def _hooked_CreateProcessA(
    app_name,
    cmd_line,
    proc_attr,
    thread_attr,
    inherit_handles,
    creation_flags,
    environment,
    current_dir,
    startup_info,
    proc_info,
):
    """Hook for kernel32!CreateProcessA.

    Same rewrapping logic as CreateProcessW but for ANSI variant.
    """
    original = _hook_manager.get_original("CreateProcessA", CreateProcessA_t)

    # Anti-recursion: child runners don't rewrap
    if _is_child_runner:
        return original(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )

    # Decode ANSI cmd_line to str for checking
    cmd_str = None
    if cmd_line:
        try:
            cmd_str = (
                cmd_line.decode("utf-8")
                if isinstance(cmd_line, bytes)
                else cmd_line
            )
        except (UnicodeDecodeError, AttributeError):
            cmd_str = None

    if not cmd_str or _is_already_sandboxed(cmd_str):
        return original(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )

    # Rewrap: launch child through sandbox_runner
    try:
        new_cmd = _build_wrapped_cmdline(cmd_str)
        new_cmd_bytes = new_cmd.encode("utf-8")
        logger.debug("CreateProcessA rewrapped: %s", new_cmd[:200])

        return original(
            None,  # app_name = None
            new_cmd_bytes,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )
    except Exception as e:
        logger.debug("CreateProcessA rewrap failed: %s, falling back", e)
        return original(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            environment,
            current_dir,
            startup_info,
            proc_info,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Hook installation
# ═══════════════════════════════════════════════════════════════════════════════


def _install_hooks() -> bool:
    """Install all NT API hooks. Returns True if at least one succeeded."""
    global _hook_manager

    _hook_manager = HookManager()

    # NT file API hooks
    _hook_manager.add(
        "ntdll.dll", "NtCreateFile", _hooked_NtCreateFile, NtCreateFile_t
    )
    _hook_manager.add(
        "ntdll.dll", "NtOpenFile", _hooked_NtOpenFile, NtOpenFile_t
    )
    _hook_manager.add(
        "ntdll.dll", "NtDeleteFile", _hooked_NtDeleteFile, NtDeleteFile_t
    )

    # Process creation hooks for recursive sandboxing
    _hook_manager.add(
        "kernel32.dll",
        "CreateProcessW",
        _hooked_CreateProcessW,
        CreateProcessW_t,
    )
    _hook_manager.add(
        "kernel32.dll",
        "CreateProcessA",
        _hooked_CreateProcessA,
        CreateProcessA_t,
    )

    count = _hook_manager.install_all()
    logger.info("Installed %d/%d hooks", count, len(_hook_manager))
    return count > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════════


def main() -> int:
    """Main entry point for the sandbox runner process."""
    global _policy, _shm, _session_id, _python_exe, _is_child_runner

    if len(sys.argv) < 3:
        print(
            "Usage: python -m qwenpaw.sandbox.windows_ctypes_hook.sandbox_runner "
            "<session_id> <b64_cmd> [b64_cwd]",
            file=sys.stderr,
        )
        return 1

    _session_id = sys.argv[1]
    b64_cmd = sys.argv[2]
    b64_cwd = sys.argv[3] if len(sys.argv) > 3 else None

    # Decode the command
    try:
        cmd = base64.b64decode(b64_cmd).decode("utf-8")
    except Exception as e:
        print(f"Failed to decode command: {e}", file=sys.stderr)
        return 1

    # Decode cwd if provided (parent sends it base64-encoded)
    cwd = None
    if b64_cwd:
        try:
            cwd = base64.b64decode(b64_cwd).decode("utf-8")
        except Exception:
            pass

    _python_exe = sys.executable

    # Detect if we're a child sandbox_runner (spawned by a parent's
    # CreateProcessW hook). If so, we still install NT file hooks to protect
    # I/O in this process, but we do NOT rewrap CreateProcessW calls to
    # avoid infinite recursion.
    _is_child_runner = os.environ.get(_ENV_SANDBOX_SESSION) == _session_id

    # Set/update the environment variable. Child processes inherit this.
    os.environ[_ENV_SANDBOX_SESSION] = _session_id

    logger.info(
        "sandbox_runner starting: session=%s, child=%s, cmd=%s",
        _session_id,
        _is_child_runner,
        cmd[:200],
    )

    # Step 1: Open shared memory and read policy
    try:
        _shm = SharedMemoryReader(_session_id)
        _shm.open()
        policy_json = _shm.read_policy_json()
        _policy = PolicyChecker(policy_json)
        logger.info(
            "Policy loaded: %d rules, allow_read_all=%s, deny_network=%s",
            len(_policy.rules),
            _policy.allow_read_all,
            _policy.deny_network,
        )
    except Exception as e:
        print(f"Failed to load policy: {e}", file=sys.stderr)
        return 1

    # Step 2: Install hooks
    if not _install_hooks():
        print("Warning: no hooks were installed", file=sys.stderr)
        # Continue anyway — at least we get the policy checking on CreateProcess

    # Step 3: Execute the target command
    # If this is a child runner, the command we received was already the full
    # CreateProcessW command line (e.g. "cmd.exe /c echo hello"). We must NOT
    # wrap it in another shell (shell=True adds cmd.exe /c again).
    # Top-level runners use shell=True for user convenience.
    use_shell = not _is_child_runner
    try:
        result = subprocess.run(
            cmd,
            shell=use_shell,
            cwd=cwd,
            capture_output=True,
        )
    except Exception as e:
        print(f"Command execution failed: {e}", file=sys.stderr)
        return 1
    finally:
        # Uninstall hooks before any cleanup I/O
        if _hook_manager:
            _hook_manager.uninstall_all()

    # Step 4: Output results
    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()

    # Step 5: Cleanup
    if _shm:
        _shm.close()

    logger.info("sandbox_runner exiting: code=%d", result.returncode)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
