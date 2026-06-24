# -*- coding: utf-8 -*-

import ctypes
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from qwenpaw.sandbox.windows_native_sandbox import (
    _AC_PROFILE_PREFIX,
    _load_dlls,
    _psid_to_string,
    _resolve_capability_sids,
    create_appcontainer_profile,
    delete_appcontainer_profile,
)


def test_perm(
    label: str, path: str, sid_string: str, perm_suffix: str
) -> float:
    """测试一种权限语法的耗时。"""
    perm = f"*{sid_string}:{perm_suffix}"
    sid_ref = f"*{sid_string}"

    # Grant
    start = time.perf_counter()
    result = subprocess.run(
        ["icacls", path, "/grant", perm, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    elapsed = time.perf_counter() - start
    status = (
        "OK" if result.returncode == 0 else f"FAIL(rc={result.returncode})"
    )
    if result.returncode != 0:
        status += f" — {result.stderr.strip()[:100]}"
    print(
        f"  [{elapsed * 1000:8.1f} ms] {label:30s} perm={perm_suffix:20s} — {status}"
    )

    # Remove (cleanup)
    subprocess.run(
        ["icacls", path, "/remove", sid_ref, "/remove:d", sid_ref, "/C"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )

    return elapsed


def main():
    if sys.platform != "win32":
        print("Windows only")
        sys.exit(1)

    _load_dlls()

    # 创建 AppContainer profile
    profile_name = f"{_AC_PROFILE_PREFIX}.bench_{secrets.token_hex(4)}"
    cap_array, cap_count = _resolve_capability_sids([])
    ac_sid = create_appcontainer_profile(profile_name, cap_array, cap_count)
    sid_string = _psid_to_string(ac_sid)

    print("=" * 70)
    print("  icacls 性能测试")
    print("=" * 70)
    print(f"  SID: {sid_string}")

    # 测试目标: C:\Users\mkh (有大量子目录，是慢的根源)
    test_path = os.environ.get("USERPROFILE")
    print(f"  测试路径: {test_path}")
    print()

    # 各种 ACE 语法
    tests = [
        ("A: (OI)(CI)RX (全继承)", "(OI)(CI)RX"),
        ("B: (RX) (默认)", "(RX)"),
        ("C: (NP)(RX)", "(NP)(RX)"),
        ("D: (NP)RX", "(NP)RX"),
        ("E: (X) only", "(X)"),
        ("F: (NP)(X)", "(NP)(X)"),
        ("G: (CI)(RX)", "(CI)(RX)"),
        ("H: (OI)(RX)", "(OI)(RX)"),
    ]

    print(f"  {'─' * 65}")
    for label, perm_suffix in tests:
        test_perm(label, test_path, sid_string, perm_suffix)
    print(f"  {'─' * 65}")

    # 对比: 在一个新建空目录上测试（应该都很快）
    import tempfile

    tmp = tempfile.mkdtemp(prefix="bench_np_")
    print(f"\n  对比 — 空目录: {tmp}")
    print(f"  {'─' * 65}")
    for label, perm_suffix in tests[:4]:
        test_perm(f"(empty) {label}", tmp, sid_string, perm_suffix)
    print(f"  {'─' * 65}")

    # 清理
    delete_appcontainer_profile(profile_name)
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    # print(f"\n  结论: 如果 (NP) 标志能显著减少耗时，则改用 (NP)(RX)。")
    # print(f"  如果仍然很慢，说明 icacls 本身会遍历子目录更新安全描述符，")
    # print(f"  可能需要改用 Win32 API (SetNamedSecurityInfoW) 直接操作。")


if __name__ == "__main__":
    main()
