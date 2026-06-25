# -*- coding: utf-8 -*-
# pylint: disable=unused-argument,protected-access,unused-variable
"""Unit tests for Windows hook-based sandbox (DLL injection)."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
from unittest.mock import MagicMock, patch

from qwenpaw.sandbox import (
    MountSpec,
    SandboxCapability,
    SandboxConfig,
    SandboxMode,
)
from qwenpaw.sandbox.windows_sandbox import (
    WindowsSandbox,
    _compile_policy,
    probe_windows_hook,
)

# ============================================================================
# probe_windows_hook() — platform detection
# ============================================================================


class TestProbeWindowsHook:
    """Test Windows hook sandbox probing logic."""

    @patch("qwenpaw.sandbox.windows_sandbox.sys.platform", "linux")
    def test_not_windows(self):
        available, reason = probe_windows_hook()
        assert available is False
        assert "Not running on Windows" in reason

    @patch("qwenpaw.sandbox.windows_sandbox.sys.platform", "win32")
    @patch("qwenpaw.sandbox.windows_sandbox.struct.calcsize", return_value=4)
    def test_32bit_python(self, mock_calcsize):
        available, reason = probe_windows_hook()
        assert available is False
        assert "64-bit" in reason

    @patch("qwenpaw.sandbox.windows_sandbox.sys.platform", "win32")
    @patch("qwenpaw.sandbox.windows_sandbox.struct.calcsize", return_value=8)
    @patch(
        "qwenpaw.sandbox.windows_sandbox._find_sandbox_dll",
        return_value=None,
    )
    def test_dll_not_found(self, mock_find_dll, mock_calcsize):
        available, reason = probe_windows_hook()
        assert available is False
        assert "not found" in reason

    @patch("qwenpaw.sandbox.windows_sandbox.sys.platform", "win32")
    @patch("qwenpaw.sandbox.windows_sandbox.struct.calcsize", return_value=8)
    @patch(
        "qwenpaw.sandbox.windows_sandbox._find_sandbox_dll",
        return_value="C:\\path\\to\\sandbox_hook.dll",
    )
    def test_all_requirements_met(self, mock_find_dll, mock_calcsize):
        available, reason = probe_windows_hook()
        assert available is True
        assert "sandbox_hook.dll" in reason


# ============================================================================
# _compile_policy() — policy compilation (rule generation)
# ============================================================================


class TestCompilePolicy:
    """Test that access rules are correctly generated from SandboxConfig."""

    def test_basic_workspace_rule(self):
        config = SandboxConfig(
            mode=SandboxMode.HOOK,
            workspace_dir="C:\\Users\\foo\\project",
            mounts=[MountSpec(path="C:\\Users\\foo\\project", writable=True)],
        )
        policy_bytes = _compile_policy(config, "test-session-001")
        policy = json.loads(policy_bytes.decode("utf-8"))

        assert policy["session_id"] == "test-session-001"
        assert isinstance(policy["rules"], list)

        # Workspace should have "rw" access
        ws_rules = [
            r
            for r in policy["rules"]
            if "project" in r["path"].lower() and r["access"] == "rw"
        ]
        assert len(ws_rules) >= 1

    def test_deny_paths_have_highest_priority(self):
        config = SandboxConfig(
            mode=SandboxMode.HOOK,
            workspace_dir="C:\\Users\\foo\\project",
            mounts=[MountSpec(path="C:\\Users\\foo\\project", writable=True)],
            deny_paths=["C:\\Users\\foo\\.ssh", "C:\\Users\\foo\\.aws"],
        )
        policy_bytes = _compile_policy(config, "test-session-002")
        policy = json.loads(policy_bytes.decode("utf-8"))

        # Deny rules should appear first in the list
        deny_rules = [r for r in policy["rules"] if r["access"] == "deny"]
        assert len(deny_rules) == 2
        assert policy["rules"][0]["access"] == "deny"
        assert policy["rules"][1]["access"] == "deny"

    def test_readonly_mount(self):
        config = SandboxConfig(
            mode=SandboxMode.HOOK,
            workspace_dir="C:\\Users\\foo\\project",
            mounts=[
                MountSpec(path="C:\\Users\\foo\\project", writable=True),
                MountSpec(path="D:\\data", writable=False, executable=True),
            ],
        )
        policy_bytes = _compile_policy(config, "test-session-003")
        policy = json.loads(policy_bytes.decode("utf-8"))

        data_rules = [
            r
            for r in policy["rules"]
            if r["path"] == os.path.normpath("D:\\data")
        ]
        assert len(data_rules) == 1
        assert data_rules[0]["access"] == "rx"

    def test_executable_false(self):
        config = SandboxConfig(
            mode=SandboxMode.HOOK,
            workspace_dir="C:\\Users\\foo\\project",
            mounts=[
                MountSpec(path="C:\\Users\\foo\\project", writable=True),
                MountSpec(
                    path="D:\\untrusted",
                    writable=False,
                    executable=False,
                ),
            ],
        )
        policy_bytes = _compile_policy(config, "test-session-004")
        policy = json.loads(policy_bytes.decode("utf-8"))

        untrusted_rules = [
            r for r in policy["rules"] if "untrusted" in r["path"].lower()
        ]
        assert len(untrusted_rules) == 1
        assert untrusted_rules[0]["access"] == "r"


# ============================================================================
# WindowsSandbox execution tests (mocked)
# ============================================================================


class TestWindowsSandboxExecution:
    """Test WindowsSandbox.execute() with mocked Win32 calls."""

    def _make_config(self):
        return SandboxConfig(
            mode=SandboxMode.HOOK,
            workspace_dir="C:\\Users\\foo\\project",
            mounts=[MountSpec(path="C:\\Users\\foo\\project", writable=True)],
            deny_paths=["~\\.ssh"],
            timeout_seconds=30,
        )

    def test_execute_success(self):
        config = self._make_config()
        sandbox = WindowsSandbox(config)
        sandbox._initialized = True
        sandbox._session_id = "test-session"
        sandbox._dll_path = "C:\\path\\sandbox_hook.dll"
        sandbox._shm_view = ctypes.c_void_p(0)
        sandbox._shm_handle = ctypes.c_void_p(0)

        with patch(
            "qwenpaw.sandbox.windows_sandbox._launch_sandboxed_process_sync",
            return_value=(0, "hello world\n", "", False),
        ):
            result = asyncio.run(sandbox.execute("echo hello world"))

        assert result.exit_code == 0
        assert result.stdout == "hello world\n"
        assert result.sandbox_violation is None

    def test_execute_violation_from_stderr(self):
        config = self._make_config()
        sandbox = WindowsSandbox(config)
        sandbox._initialized = True
        sandbox._session_id = "test-session"
        sandbox._dll_path = "C:\\path\\sandbox_hook.dll"
        sandbox._shm_view = ctypes.c_void_p(0)
        sandbox._shm_handle = ctypes.c_void_p(0)

        with patch(
            "qwenpaw.sandbox.windows_sandbox._launch_sandboxed_process_sync",
            return_value=(1, "", "Access is denied.\n", False),
        ):
            result = asyncio.run(sandbox.execute("type C:\\.ssh\\id_rsa"))

        assert result.exit_code == 1
        assert result.sandbox_violation is not None
        assert "Access is denied" in result.sandbox_violation

    def test_execute_timeout(self):
        config = self._make_config()
        config.timeout_seconds = 1
        sandbox = WindowsSandbox(config)
        sandbox._initialized = True
        sandbox._session_id = "test-session"
        sandbox._dll_path = "C:\\path\\sandbox_hook.dll"
        sandbox._shm_view = ctypes.c_void_p(0)
        sandbox._shm_handle = ctypes.c_void_p(0)

        with patch(
            "qwenpaw.sandbox.windows_sandbox._launch_sandboxed_process_sync",
            return_value=(-1, "", "", True),
        ):
            result = asyncio.run(sandbox.execute("ping -t localhost"))

        assert result.timed_out is True
        assert result.exit_code == -1


# ============================================================================
# Governance: sandbox_available=False → SANDBOX_FALLBACK escalates to ASK
# ============================================================================


class TestGovernanceSandboxUnavailable:
    """Test SANDBOX_FALLBACK escalates to ASK when sandbox unavailable."""

    def test_sandbox_fallback_becomes_ask(self):
        """When sandbox is unavailable, SANDBOX_FALLBACK should become ASK."""
        cap = SandboxCapability(
            supported=False,
            mode=SandboxMode.NONE,
            reason="sandbox_hook.dll not found",
        )

        from qwenpaw.governance.resource_governor import ResourceGovernor

        governor = ResourceGovernor(workspace_dir="/tmp/test_ws")

        with (
            patch(
                "qwenpaw.governance.resource_governor.load_governance_policy",
            ) as mock_load,
            patch("pathlib.Path.mkdir"),
            patch(
                "qwenpaw.governance.resource_governor.probe_sandbox_support",
                return_value=cap,
            ),
        ):
            mock_policy = MagicMock()
            mock_load.return_value = mock_policy
            governor.start()

        assert governor.sandbox_available is False
        assert (
            governor.sandbox_capability.reason == "sandbox_hook.dll not found"
        )
