# -*- coding: utf-8 -*-
"""Windows DLL injection sandbox for file I/O isolation.

This package uses a native DLL (sandbox_hook.dll) that is injected into the
target process and all its child processes to enforce filesystem access policies.

Unlike the pure-Python ctypes approach, DLL injection propagates automatically
to all child processes regardless of their language runtime, solving the
child-process sandboxing problem.

Architecture:
  1. Parent compiles policy and creates named shared memory
  2. Parent creates target process in CREATE_SUSPENDED state
  3. Parent injects sandbox_hook.dll via CreateRemoteThread + LoadLibraryW
  4. DLL reads policy from shared memory and installs NT API hooks
  5. DLL hooks CreateProcessW/A to inject itself into grandchildren
  6. Parent resumes the target process
  7. All file I/O in the target and its descendants is policy-checked
"""
