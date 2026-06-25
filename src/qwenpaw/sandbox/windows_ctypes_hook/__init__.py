# -*- coding: utf-8 -*-
"""Pure Python ctypes inline hooking sandbox for Windows x64.

This package implements NT API hooking without any compiled C code or
external libraries (no Detours, no MSVC toolchain required). All hook
logic is Python, making it fully debuggable with print/logging/pdb.

Architecture:
  Parent (WindowsHookSandbox) launches sandbox_runner.py as a subprocess.
  The runner installs inline hooks on NT APIs in its own process, then
  executes the target command. File access is checked against the policy
  in shared memory; violations are logged to the ring buffer.
"""
