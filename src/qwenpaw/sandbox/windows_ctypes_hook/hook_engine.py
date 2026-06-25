# -*- coding: utf-8 -*-
"""Generic x64 inline hook engine using ctypes.

Replaces Microsoft Detours entirely — no compiled code needed.

Hook strategy (universal E9 relay):
  1. Allocate a relay thunk within ±2GB of target (for E9 rel32 range)
  2. Write relay thunk: absolute JMP to Python callback (14 bytes)
  3. Allocate trampoline: saved prologue bytes + absolute JMP back
  4. Overwrite target's first 5 bytes with E9 rel32 → relay thunk

The trampoline copies enough complete instructions (determined by a minimal
x64 length decoder) to cover the 5-byte E9 patch, then jumps back to the
first intact instruction in the original function.

Special case: if the target already has an E9 JMP (third-party AV/EDR hook),
we resolve its destination and chain through it via the trampoline.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import struct
import sys
from typing import Any, Optional

assert sys.platform == "win32", "This module is Windows-only"

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Windows constants
# ═══════════════════════════════════════════════════════════════════════════════

PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

# ═══════════════════════════════════════════════════════════════════════════════
# Kernel32 bindings
# ═══════════════════════════════════════════════════════════════════════════════

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.GetModuleHandleW.restype = ctypes.wintypes.HMODULE
_kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

_kernel32.GetProcAddress.restype = ctypes.c_void_p
_kernel32.GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]

_kernel32.VirtualAlloc.restype = ctypes.c_void_p
_kernel32.VirtualAlloc.argtypes = [
    ctypes.c_void_p,  # lpAddress
    ctypes.c_size_t,  # dwSize
    ctypes.wintypes.DWORD,  # flAllocationType
    ctypes.wintypes.DWORD,  # flProtect
]

_kernel32.VirtualFree.restype = ctypes.wintypes.BOOL
_kernel32.VirtualFree.argtypes = [
    ctypes.c_void_p,  # lpAddress
    ctypes.c_size_t,  # dwSize
    ctypes.wintypes.DWORD,  # dwFreeType
]

_kernel32.VirtualProtect.restype = ctypes.wintypes.BOOL
_kernel32.VirtualProtect.argtypes = [
    ctypes.c_void_p,  # lpAddress
    ctypes.c_size_t,  # dwSize
    ctypes.wintypes.DWORD,  # flNewProtect
    ctypes.POINTER(ctypes.wintypes.DWORD),  # lpflOldProtect
]

_kernel32.FlushInstructionCache.restype = ctypes.wintypes.BOOL
_kernel32.FlushInstructionCache.argtypes = [
    ctypes.wintypes.HANDLE,  # hProcess
    ctypes.c_void_p,  # lpBaseAddress
    ctypes.c_size_t,  # dwSize
]

_kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
_kernel32.GetCurrentProcess.argtypes = []

# ═══════════════════════════════════════════════════════════════════════════════
# Expected prologue patterns for validation
# ═══════════════════════════════════════════════════════════════════════════════

# All Nt* syscall stubs in ntdll.dll start with:
#   4C 8B D1    mov r10, rcx
#   B8 xx xx xx xx    mov eax, <syscall_number>
# Total: 7 bytes of predictable pattern (first 4 always identical)
_NT_SYSCALL_PROLOGUE = b"\x4c\x8b\xd1\xb8"

# kernel32!CreateProcessW starts with a standard function prologue.
# We don't strictly validate kernel32 functions since they vary more,
# but we do check that the first byte isn't 0xCC (int3 / breakpoint).
_BREAKPOINT_BYTE = 0xCC


# ═══════════════════════════════════════════════════════════════════════════════
# Minimal x64 instruction length decoder
# ═══════════════════════════════════════════════════════════════════════════════


def _x64_insn_length(code: bytes, offset: int = 0) -> int:
    """Determine the length of the x64 instruction at code[offset].

    This is a MINIMAL decoder that handles the common instructions found in
    Windows DLL function prologues. It does NOT handle all x64 instructions.
    Returns 0 if the instruction cannot be decoded (caller should bail out).

    Handled patterns:
      - REX.W/REX.R/REX.B prefixes (40-4F)
      - MOV reg,[rsp+disp8]  /  MOV [rsp+disp8],reg  (SIB byte + disp8)
      - MOV reg,[rsp+disp32] /  MOV [rsp+disp32],reg (SIB byte + disp32)
      - SUB/ADD rsp, imm8/imm32
      - PUSH/POP reg (including REX variants)
      - LEA reg, [rsp+disp8/32]
      - MOV r10, rcx (4C 8B D1) — syscall stub
      - MOV eax, imm32 (B8+rd)
      - TEST byte ptr [abs32], imm8 (F6 04 25 ... )
      - Jcc short (70-7F + rel8)
      - SYSCALL (0F 05), RET (C3), NOP (90), INT3 (CC)
      - XOR reg,reg / MOV reg,reg / TEST reg,reg
    """
    if offset >= len(code):
        return 0

    pos = offset
    end = len(code)

    # Skip prefixes (REX, 66h operand-size, 67h address-size)
    has_rex = False
    rex_w = False
    op_size_prefix = False

    while pos < end:
        b = code[pos]
        if 0x40 <= b <= 0x4F:
            has_rex = True
            rex_w = bool(b & 0x08)
            pos += 1
        elif b == 0x66:
            op_size_prefix = True
            pos += 1
        elif b == 0x67:
            pos += 1
        else:
            break

    if pos >= end:
        return 0

    opcode = code[pos]
    pos += 1

    # ─── Single-byte opcodes ─────────────────────────────────────────────

    # PUSH reg (50-57), POP reg (58-5F)
    if 0x50 <= opcode <= 0x5F:
        return pos - offset

    # RET (C3)
    if opcode == 0xC3:
        return pos - offset

    # NOP (90), INT3 (CC)
    if opcode in (0x90, 0xCC):
        return pos - offset

    # MOV reg, imm32/imm64 (B8-BF)
    if 0xB8 <= opcode <= 0xBF:
        if rex_w:
            return (pos + 8) - offset  # imm64
        return (pos + 4) - offset  # imm32

    # Jcc short (70-7F): opcode + rel8
    if 0x70 <= opcode <= 0x7F:
        return (pos + 1) - offset

    # JMP short (EB): opcode + rel8
    if opcode == 0xEB:
        return (pos + 1) - offset

    # JMP rel32 (E9): opcode + rel32
    if opcode == 0xE9:
        return (pos + 4) - offset

    # CALL rel32 (E8): opcode + rel32
    if opcode == 0xE8:
        return (pos + 4) - offset

    # ─── Two-byte opcode (0F xx) ─────────────────────────────────────────

    if opcode == 0x0F:
        if pos >= end:
            return 0
        opcode2 = code[pos]
        pos += 1

        # SYSCALL (0F 05)
        if opcode2 == 0x05:
            return pos - offset

        # Jcc near (0F 80-8F): + rel32
        if 0x80 <= opcode2 <= 0x8F:
            return (pos + 4) - offset

        return 0  # Unknown 0F xx

    # ─── ModRM-based opcodes ─────────────────────────────────────────────

    # Opcodes that use ModRM byte:
    # 89/8B (MOV), 01/03/29/2B (ADD/SUB), 09/0B/21/23/31/33 (OR/AND/XOR),
    # 85 (TEST), 39/3B (CMP), 8D (LEA), 63 (MOVSXD)
    modrm_opcodes = {
        0x01,
        0x03,
        0x09,
        0x0B,
        0x21,
        0x23,
        0x29,
        0x2B,
        0x31,
        0x33,
        0x39,
        0x3B,
        0x63,
        0x85,
        0x87,
        0x89,
        0x8B,
        0x8D,
    }

    # Group opcodes with ModRM: 80-83 (imm ALU), C7 (MOV imm), F7 (TEST/NOT/NEG)
    group_opcodes = {0x80, 0x81, 0x83, 0xC7, 0xF7}

    # F6 (byte TEST/NOT/NEG) — has imm8 for /0 and /1
    if opcode == 0xF6:
        if pos >= end:
            return 0
        modrm = code[pos]
        pos += 1
        mod = (modrm >> 6) & 3
        reg_op = (modrm >> 3) & 7
        rm = modrm & 7

        # Handle SIB
        if mod != 3 and rm == 4:
            pos += 1  # SIB byte

        # Handle displacement
        if mod == 1:
            pos += 1  # disp8
        elif mod == 2:
            pos += 4  # disp32
        elif mod == 0 and rm == 5:
            pos += 4  # RIP-relative disp32

        # TEST (reg_op=0,1) has imm8
        if reg_op <= 1:
            pos += 1

        return pos - offset

    if opcode in modrm_opcodes:
        if pos >= end:
            return 0
        modrm = code[pos]
        pos += 1
        mod = (modrm >> 6) & 3
        rm = modrm & 7

        # Handle SIB byte (rm=4 and mod!=3)
        if mod != 3 and rm == 4:
            pos += 1  # SIB byte

        # Handle displacement
        if mod == 1:
            pos += 1  # disp8
        elif mod == 2:
            pos += 4  # disp32
        elif mod == 0 and rm == 5:
            pos += 4  # RIP-relative disp32

        return pos - offset

    if opcode in group_opcodes:
        if pos >= end:
            return 0
        modrm = code[pos]
        pos += 1
        mod = (modrm >> 6) & 3
        rm = modrm & 7

        # Handle SIB byte
        if mod != 3 and rm == 4:
            pos += 1  # SIB byte

        # Handle displacement
        if mod == 1:
            pos += 1  # disp8
        elif mod == 2:
            pos += 4  # disp32
        elif mod == 0 and rm == 5:
            pos += 4  # RIP-relative disp32

        # Handle immediate
        if opcode == 0x80:
            pos += 1  # imm8
        elif opcode == 0x81:
            pos += 4  # imm32
        elif opcode == 0x83:
            pos += 1  # imm8
        elif opcode == 0xC7:
            pos += 4  # imm32
        elif opcode == 0xF7:
            reg_op = (modrm >> 3) & 7
            if reg_op <= 1:  # TEST
                pos += 4  # imm32

        return pos - offset

    # Unknown opcode
    return 0


def _calc_trampoline_size(code: bytes, min_bytes: int) -> int:
    """Calculate how many bytes to copy for the trampoline.

    Walks instructions from the start until we've covered at least min_bytes.
    Returns the total bytes (aligned to instruction boundary), or 0 on failure.
    """
    total = 0
    while total < min_bytes:
        length = _x64_insn_length(code, total)
        if length == 0:
            return 0  # Cannot decode — bail out
        total += length
    return total


# ═══════════════════════════════════════════════════════════════════════════════
# InlineHook class
# ═══════════════════════════════════════════════════════════════════════════════


class InlineHook:
    """Manages a single x64 inline hook.

    Usage:
        hook = InlineHook("ntdll.dll", "NtCreateFile", my_callback, NtCreateFile_t)
        hook.install()
        original = hook.get_original()  # callable to invoke original function
        ...
        hook.uninstall()  # restore original bytes
    """

    PATCH_SIZE = 5  # E9 rel32 (universal patch size)

    def __init__(
        self,
        dll_name: str,
        func_name: str,
        hook_callback: Any,
        func_type: Any,
    ):
        """Initialize the hook (does not install yet).

        Args:
            dll_name: DLL containing the target function (e.g. "ntdll.dll").
            func_name: Export name of the target function.
            hook_callback: Python function matching func_type signature.
            func_type: ctypes WINFUNCTYPE defining the function signature.
        """
        self._dll_name = dll_name
        self._func_name = func_name
        self._func_type = func_type
        self._target_addr: int = 0
        self._trampoline_addr: int = 0
        self._relay_addr: int = 0  # Relay thunk for absolute JMP to callback
        self._original_bytes: bytes = b""  # Bytes we overwrite (for uninstall)
        self._installed: bool = False

        # Create the ctypes callback object and hold a strong reference.
        # If this gets garbage-collected, the hook will crash the process.
        self._callback_obj = func_type(hook_callback)
        self._callback_addr: int = 0

    @property
    def installed(self) -> bool:
        """Whether the hook is currently active."""
        return self._installed

    @property
    def target_address(self) -> int:
        """Address of the hooked function (0 if not resolved)."""
        return self._target_addr

    def install(self) -> bool:
        """Install the inline hook. Returns True on success.

        Strategy:
          1. Resolve target function address
          2. Validate prologue
          3. Determine trampoline size (instruction-boundary aligned)
          4. Allocate relay thunk (within ±2GB) and trampoline
          5. Write relay: absolute JMP → callback
          6. Write trampoline: saved bytes + absolute JMP back
          7. Overwrite target's first 5 bytes with E9 rel32 → relay
        """
        if self._installed:
            logger.warning(
                "Hook already installed: %s!%s",
                self._dll_name,
                self._func_name,
            )
            return True

        # Step 1: Resolve target address
        h_dll = _kernel32.GetModuleHandleW(self._dll_name)
        if not h_dll:
            logger.error(
                "GetModuleHandleW(%s) failed: %d",
                self._dll_name,
                ctypes.get_last_error(),
            )
            return False

        self._target_addr = _kernel32.GetProcAddress(
            h_dll, self._func_name.encode("ascii")
        )
        if not self._target_addr:
            logger.error(
                "GetProcAddress(%s, %s) failed: %d",
                self._dll_name,
                self._func_name,
                ctypes.get_last_error(),
            )
            return False

        # Step 2: Validate prologue
        if not self._validate_prologue():
            logger.error(
                "Prologue validation failed for %s!%s at 0x%016X",
                self._dll_name,
                self._func_name,
                self._target_addr,
            )
            return False

        # Step 3: Determine hook strategy
        first_byte = self._read_memory(self._target_addr, 1)[0]

        if first_byte == 0xE9:
            # === THIRD-PARTY E9 HOOK ===
            # Target already has a 5-byte E9 rel32 from AV/EDR.
            # Trampoline = absolute JMP to third-party's target (chains through).
            self._original_bytes = self._read_memory(
                self._target_addr, self.PATCH_SIZE
            )
            rel32 = struct.unpack_from("<i", self._original_bytes, 1)[0]
            thirdparty_target = (self._target_addr + 5) + rel32

            # Trampoline: absolute JMP to third-party target
            self._trampoline_addr = _kernel32.VirtualAlloc(
                None,
                64,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            if not self._trampoline_addr:
                logger.error(
                    "VirtualAlloc for trampoline failed: %d",
                    ctypes.get_last_error(),
                )
                return False

            trampoline = bytearray(14)
            trampoline[0:6] = b"\xff\x25\x00\x00\x00\x00"
            trampoline[6:14] = struct.pack("<Q", thirdparty_target)
            self._write_memory(self._trampoline_addr, bytes(trampoline))

            logger.debug(
                "E9 chain hook: %s!%s, trampoline → 0x%016X (third-party)",
                self._dll_name,
                self._func_name,
                thirdparty_target,
            )
        else:
            # === STANDARD HOOK (E9 relay + instruction-aligned trampoline) ===
            # Read enough bytes to decode instructions covering our 5-byte patch.
            prologue = self._read_memory(self._target_addr, 32)  # Read plenty
            trampoline_copy_size = _calc_trampoline_size(
                prologue, self.PATCH_SIZE
            )

            if trampoline_copy_size == 0:
                logger.error(
                    "Cannot decode prologue for %s!%s at 0x%016X: %s",
                    self._dll_name,
                    self._func_name,
                    self._target_addr,
                    prologue[:16].hex(" "),
                )
                return False

            self._original_bytes = self._read_memory(
                self._target_addr, self.PATCH_SIZE
            )

            # Trampoline: copied instructions + absolute JMP to target+N
            tramp_total = trampoline_copy_size + 14  # saved bytes + JMP back
            self._trampoline_addr = _kernel32.VirtualAlloc(
                None,
                max(64, tramp_total),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            if not self._trampoline_addr:
                logger.error(
                    "VirtualAlloc for trampoline failed: %d",
                    ctypes.get_last_error(),
                )
                return False

            trampoline = bytearray(tramp_total)
            trampoline[0:trampoline_copy_size] = prologue[
                :trampoline_copy_size
            ]
            trampoline[trampoline_copy_size : trampoline_copy_size + 6] = (
                b"\xff\x25\x00\x00\x00\x00"
            )
            jump_back = self._target_addr + trampoline_copy_size
            trampoline[
                trampoline_copy_size + 6 : trampoline_copy_size + 14
            ] = struct.pack("<Q", jump_back)
            self._write_memory(self._trampoline_addr, bytes(trampoline))

            logger.debug(
                "Standard hook: %s!%s, trampoline copies %d bytes, jmp back to +%d",
                self._dll_name,
                self._func_name,
                trampoline_copy_size,
                trampoline_copy_size,
            )

        # Step 4: Allocate relay thunk near target (within ±2GB for E9 rel32)
        self._relay_addr = self._alloc_near(self._target_addr, 64)
        if not self._relay_addr:
            logger.error(
                "Failed to allocate relay thunk near %s!%s",
                self._dll_name,
                self._func_name,
            )
            self._free_allocations()
            return False

        # Step 5: Write relay thunk (absolute JMP to Python callback)
        self._callback_addr = ctypes.cast(
            self._callback_obj, ctypes.c_void_p
        ).value
        relay = bytearray(14)
        relay[0:6] = b"\xff\x25\x00\x00\x00\x00"
        relay[6:14] = struct.pack("<Q", self._callback_addr)
        self._write_memory(self._relay_addr, bytes(relay))

        # Step 6: Compute E9 rel32 displacement to relay
        rel32_to_relay = self._relay_addr - (self._target_addr + 5)
        if not (-(2**31) <= rel32_to_relay < 2**31):
            logger.error("Relay thunk too far from target for E9 rel32")
            self._free_allocations()
            return False

        hook_patch = b"\xe9" + struct.pack("<i", rel32_to_relay)

        # Step 7: Write the 5-byte E9 patch to the target
        old_protect = ctypes.wintypes.DWORD(0)
        _kernel32.VirtualProtect(
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        self._write_memory(self._target_addr, hook_patch)

        _kernel32.VirtualProtect(
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
            old_protect.value,
            ctypes.byref(old_protect),
        )

        _kernel32.FlushInstructionCache(
            _kernel32.GetCurrentProcess(),
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
        )

        self._installed = True
        logger.info(
            "Hook installed: %s!%s @ 0x%016X → callback @ 0x%016X, trampoline @ 0x%016X",
            self._dll_name,
            self._func_name,
            self._target_addr,
            self._callback_addr,
            self._trampoline_addr,
        )
        return True

    def uninstall(self) -> bool:
        """Remove the hook, restoring the original function bytes."""
        if not self._installed:
            return False

        # Restore original bytes (always 5 bytes for E9 patch)
        old_protect = ctypes.wintypes.DWORD(0)
        _kernel32.VirtualProtect(
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )

        self._write_memory(self._target_addr, self._original_bytes)

        _kernel32.VirtualProtect(
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
            old_protect.value,
            ctypes.byref(old_protect),
        )

        _kernel32.FlushInstructionCache(
            _kernel32.GetCurrentProcess(),
            ctypes.c_void_p(self._target_addr),
            ctypes.c_size_t(self.PATCH_SIZE),
        )

        # Free allocated memory
        self._free_allocations()

        self._installed = False
        logger.info("Hook uninstalled: %s!%s", self._dll_name, self._func_name)
        return True

    def get_original(self) -> Any:
        """Get a callable for the original function (via trampoline).

        Returns a ctypes function pointer that, when called, executes
        the original function as if the hook were not installed.
        """
        if not self._trampoline_addr:
            raise RuntimeError("Hook not installed; no trampoline available")
        return ctypes.cast(
            ctypes.c_void_p(self._trampoline_addr),
            self._func_type,
        )

    def _alloc_near(self, target: int, size: int) -> int:
        """Allocate executable memory within ±2GB of target address.

        Tries candidate addresses starting close to the target and moving
        outward until VirtualAlloc succeeds. Returns 0 on failure.
        """
        alloc_granularity = 0x10000  # 64KB allocation granularity on Windows
        max_offset = 0x7FFF0000  # Just under 2GB

        # Interleave below/above to find a free slot near the target quickly.
        for step in range(1, max_offset // alloc_granularity):
            for direction in (-1, 1):
                candidate = target + direction * step * alloc_granularity
                # Align to granularity boundary
                candidate = candidate & ~(alloc_granularity - 1)
                if candidate <= 0 or candidate > 0x7FFFFFFFFFFF:
                    continue  # Out of user-mode address range

                addr = _kernel32.VirtualAlloc(
                    ctypes.c_void_p(candidate),
                    ctypes.c_size_t(size),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
                if addr:
                    # Verify it's actually within ±2GB for E9 rel32
                    diff = addr - (target + 5)
                    if -(2**31) <= diff < 2**31:
                        return addr
                    # Allocated but too far — free and continue
                    _kernel32.VirtualFree(
                        ctypes.c_void_p(addr), 0, MEM_RELEASE
                    )

        return 0

    def _free_allocations(self) -> None:
        """Free trampoline and relay thunk memory."""
        if self._trampoline_addr:
            _kernel32.VirtualFree(
                ctypes.c_void_p(self._trampoline_addr),
                0,
                MEM_RELEASE,
            )
            self._trampoline_addr = 0
        if self._relay_addr:
            _kernel32.VirtualFree(
                ctypes.c_void_p(self._relay_addr),
                0,
                MEM_RELEASE,
            )
            self._relay_addr = 0

    def _validate_prologue(self) -> bool:
        """Check that the target has an expected prologue pattern.

        For ntdll Nt* functions we expect the standard syscall stub:
          4C 8B D1 B8 xx xx xx xx  (mov r10,rcx; mov eax,<syscall_num>)

        However, security software (AV/EDR) often patches these with a
        5-byte relative JMP (E9 xx xx xx xx) to their own hook. In that
        case we still allow installation — the trampoline will chain through.
        """
        first_bytes = self._read_memory(self._target_addr, 4)

        # Reject if function has a 14-byte absolute JMP (FF 25) — already hooked by us
        if first_bytes[0:2] == b"\xff\x25":
            logger.warning(
                "%s!%s appears already hooked with FF 25 (14-byte abs JMP)",
                self._dll_name,
                self._func_name,
            )
            return False

        # Reject breakpoint byte (suggests debugger interference)
        if first_bytes[0] == _BREAKPOINT_BYTE:
            logger.warning(
                "%s!%s starts with INT3 (0xCC), possibly a breakpoint",
                self._dll_name,
                self._func_name,
            )
            return False

        # For ntdll Nt* functions, check prologue
        if (
            self._dll_name.lower() == "ntdll.dll"
            and self._func_name.startswith("Nt")
        ):
            if first_bytes[:4] == _NT_SYSCALL_PROLOGUE:
                return True  # Standard syscall stub — ideal case

            # E9 = relative JMP (5 bytes) — third-party hook (AV/EDR)
            if first_bytes[0] == 0xE9:
                logger.info(
                    "%s!%s has third-party hook (E9 rel32 JMP), "
                    "will chain through via trampoline",
                    self._dll_name,
                    self._func_name,
                )
                return True

            # Unknown prologue — reject
            logger.warning(
                "%s!%s prologue mismatch: expected 4C 8B D1 B8 or E9, got %s",
                self._dll_name,
                self._func_name,
                first_bytes[:4].hex(" "),
            )
            return False

        return True

    @staticmethod
    def _read_memory(address: int, size: int) -> bytes:
        """Read raw bytes from a memory address."""
        buf = (ctypes.c_ubyte * size)()
        ctypes.memmove(buf, ctypes.c_void_p(address), size)
        return bytes(buf)

    @staticmethod
    def _write_memory(address: int, data: bytes) -> None:
        """Write raw bytes to a memory address."""
        ctypes.memmove(ctypes.c_void_p(address), data, len(data))


# ═══════════════════════════════════════════════════════════════════════════════
# HookManager — convenience wrapper for managing multiple hooks
# ═══════════════════════════════════════════════════════════════════════════════


class HookManager:
    """Manages a collection of InlineHook instances.

    Keeps strong references to all hooks and their callbacks to prevent GC.
    Provides install_all / uninstall_all for batch operations.
    """

    def __init__(self):
        self._hooks: list[InlineHook] = []

    def add(
        self,
        dll_name: str,
        func_name: str,
        hook_callback: Any,
        func_type: Any,
    ) -> InlineHook:
        """Create and register a new hook (does not install yet)."""
        hook = InlineHook(dll_name, func_name, hook_callback, func_type)
        self._hooks.append(hook)
        return hook

    def install_all(self) -> int:
        """Install all registered hooks. Returns count of successful installs."""
        success = 0
        for hook in self._hooks:
            if hook.install():
                success += 1
        return success

    def uninstall_all(self) -> None:
        """Uninstall all hooks and free resources."""
        for hook in self._hooks:
            if hook.installed:
                hook.uninstall()

    def get_original(self, func_name: str, func_type: Any) -> Optional[Any]:
        """Get the original function callable for a hooked function."""
        for hook in self._hooks:
            if hook._func_name == func_name and hook.installed:
                return hook.get_original()
        return None

    def __len__(self) -> int:
        return len(self._hooks)
