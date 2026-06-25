/**
 * sandbox_hook.c - QwenPaw DLL-based sandbox hook implementation
 *
 * This DLL is injected into the target process (and all its children) to
 * enforce filesystem access policies. It hooks:
 *   - ntdll!NtCreateFile
 *   - ntdll!NtOpenFile
 *   - ntdll!NtDeleteFile
 *   - ntdll!NtFsControlFile  (blocks symlink/junction creation)
 *   - kernel32!CreateProcessW
 *   - kernel32!CreateProcessA
 *
 * Child process propagation:
 *   The CreateProcessW/A hooks add CREATE_SUSPENDED to the creation flags,
 *   inject this DLL into the child via CreateRemoteThread+LoadLibraryW,
 *   then resume the child's main thread. This ensures all descendants
 *   are sandboxed regardless of what language or runtime they use.
 *
 * Policy communication:
 *   The session ID is passed via the __QWENPAW_SANDBOX_SESSION environment
 *   variable. The DLL reads the policy from named shared memory on attach.
 *   The DLL path is passed via __QWENPAW_SANDBOX_DLL_PATH for child injection.
 *
 * Build: MSVC x64 or MinGW-w64 x64
 *   cl /O2 /LD sandbox_hook.c /link /OUT:sandbox_hook.dll
 *   x86_64-w64-mingw32-gcc -shared -O2 -o sandbox_hook.dll sandbox_hook.c
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sandbox_hook.h"

/* STATUS_SUCCESS may not be defined in all SDK versions */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* ===========================================================================
 * NT API type definitions (not in standard headers)
 * =========================================================================== */

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

typedef NTSTATUS (NTAPI *PFN_NtDeleteFile)(
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *PFN_NtFsControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

/* FSCTL_SET_REPARSE_POINT - used to create symlinks and junctions */
#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT 0x000900A4
#endif

typedef BOOL (WINAPI *PFN_CreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI *PFN_CreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

/* ===========================================================================
 * Global state
 * =========================================================================== */

static SANDBOX_POLICY g_policy;
static HANDLE g_shm_handle = NULL;
static LPVOID g_shm_view = NULL;
static WCHAR g_dll_path[MAX_PATH];     /* Full path to this DLL */
static WCHAR g_session_id[64];         /* Session ID from env */
static BOOL g_hooks_installed = FALSE;
static BOOL g_debug = FALSE;

/* Original function pointers (trampolines) */
static PFN_NtCreateFile    g_orig_NtCreateFile = NULL;
static PFN_NtOpenFile      g_orig_NtOpenFile = NULL;
static PFN_NtDeleteFile    g_orig_NtDeleteFile = NULL;
static PFN_NtFsControlFile g_orig_NtFsControlFile = NULL;
static PFN_CreateProcessW  g_orig_CreateProcessW = NULL;
static PFN_CreateProcessA  g_orig_CreateProcessA = NULL;

/* Trampoline buffers (allocated with VirtualAlloc, RWX) */
#define TRAMPOLINE_SIZE 64
static BYTE* g_tramp_NtCreateFile = NULL;
static BYTE* g_tramp_NtOpenFile = NULL;
static BYTE* g_tramp_NtDeleteFile = NULL;
static BYTE* g_tramp_NtFsControlFile = NULL;
static BYTE* g_tramp_CreateProcessW = NULL;
static BYTE* g_tramp_CreateProcessA = NULL;

/* ===========================================================================
 * Debug logging
 * =========================================================================== */

#define DBG(fmt, ...) do { \
    if (g_debug) { \
        char _buf[512]; \
        _snprintf(_buf, sizeof(_buf), "[sandbox_hook %u] " fmt "\n", \
                  GetCurrentProcessId(), ##__VA_ARGS__); \
        OutputDebugStringA(_buf); \
    } \
} while(0)

/* ===========================================================================
 * Minimal JSON parser (just enough for our policy format)
 * =========================================================================== */

static const char* skip_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char* parse_string(const char* p, char* out, int max_len) {
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < max_len - 1) {
        if (*p == '\\') {
            p++;
            if (*p == '\\') out[i++] = '\\';
            else if (*p == '"') out[i++] = '"';
            else if (*p == '/') out[i++] = '/';
            else if (*p == 'n') out[i++] = '\n';
            else if (*p == 't') out[i++] = '\t';
            else out[i++] = *p;
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    if (*p == '"') p++;
    return p;
}

static const char* skip_value(const char* p) {
    p = skip_ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\') p++;
            p++;
        }
        if (*p == '"') p++;
    } else if (*p == '{') {
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            else if (*p == '"') {
                p++;
                while (*p && *p != '"') { if (*p == '\\') p++; p++; }
            }
            p++;
        }
    } else if (*p == '[') {
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            if (*p == '[') depth++;
            else if (*p == ']') depth--;
            else if (*p == '"') {
                p++;
                while (*p && *p != '"') { if (*p == '\\') p++; p++; }
            }
            p++;
        }
    } else {
        while (*p && *p != ',' && *p != '}' && *p != ']') p++;
    }
    return p;
}

static BOOL parse_bool(const char* p) {
    p = skip_ws(p);
    return (strncmp(p, "true", 4) == 0);
}

/* Normalize path: lowercase, forward slash -> backslash, strip trailing backslash */
static void normalize_path_to_wchar(const char* utf8_path, WCHAR* out, int max_wchars) {
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8_path, -1, out, max_wchars);
    if (len <= 0) {
        out[0] = L'\0';
        return;
    }
    /* Lowercase and normalize separators */
    for (int i = 0; out[i]; i++) {
        if (out[i] == L'/') out[i] = L'\\';
        if (out[i] >= L'A' && out[i] <= L'Z')
            out[i] = out[i] - L'A' + L'a';
    }
    /* Strip trailing backslash (unless root like "c:\") */
    int wlen = (int)wcslen(out);
    if (wlen > 3 && out[wlen - 1] == L'\\') {
        out[wlen - 1] = L'\0';
    }
}

static BOOL parse_policy_json(const char* json, SANDBOX_POLICY* policy) {
    memset(policy, 0, sizeof(SANDBOX_POLICY));

    const char* p = skip_ws(json);
    if (*p != '{') return FALSE;
    p++;

    char key[64];
    while (*p && *p != '}') {
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p != '"') break;

        p = parse_string(p, key, sizeof(key));
        if (!p) break;
        p = skip_ws(p);
        if (*p != ':') break;
        p++;
        p = skip_ws(p);

        if (strcmp(key, "allow_read_all") == 0) {
            policy->allow_read_all = parse_bool(p);
            p = skip_value(p);
        } else if (strcmp(key, "deny_network") == 0) {
            policy->deny_network = parse_bool(p);
            p = skip_value(p);
        } else if (strcmp(key, "rules") == 0) {
            if (*p != '[') { p = skip_value(p); continue; }
            p++;  /* skip '[' */

            while (*p && *p != ']') {
                p = skip_ws(p);
                if (*p == ',') { p++; continue; }
                if (*p != '{') break;
                p++;  /* skip '{' */

                char rule_path[1024] = {0};
                char rule_access[16] = {0};

                while (*p && *p != '}') {
                    p = skip_ws(p);
                    if (*p == ',') { p++; continue; }
                    if (*p != '"') break;

                    char rkey[32];
                    p = parse_string(p, rkey, sizeof(rkey));
                    if (!p) break;
                    p = skip_ws(p);
                    if (*p != ':') break;
                    p++;
                    p = skip_ws(p);

                    if (strcmp(rkey, "path") == 0) {
                        p = parse_string(p, rule_path, sizeof(rule_path));
                    } else if (strcmp(rkey, "access") == 0) {
                        p = parse_string(p, rule_access, sizeof(rule_access));
                    } else {
                        p = skip_value(p);
                    }
                }
                if (*p == '}') p++;

                /* Add rule to policy */
                if (rule_path[0] && policy->rule_count < MAX_POLICY_RULES) {
                    POLICY_RULE* rule = &policy->rules[policy->rule_count];

                    normalize_path_to_wchar(rule_path, rule->path, MAX_PATH_LENGTH);
                    rule->path_len = (int)wcslen(rule->path);

                    if (strcmp(rule_access, "deny") == 0) {
                        rule->access = ACCESS_DENY;
                        rule->is_deny = 1;
                    } else if (strcmp(rule_access, "rw") == 0) {
                        rule->access = ACCESS_FULL;
                        rule->is_deny = 0;
                    } else if (strcmp(rule_access, "rx") == 0) {
                        rule->access = ACCESS_READ_EXECUTE;
                        rule->is_deny = 0;
                    } else {
                        rule->access = ACCESS_READ;
                        rule->is_deny = 0;
                    }

                    policy->rule_count++;
                }
            }
            if (*p == ']') p++;
        } else {
            p = skip_value(p);
        }
    }

    return TRUE;
}

/* ===========================================================================
 * Policy checking
 * =========================================================================== */

static BOOL is_subpath(const WCHAR* path, int path_len,
                       const WCHAR* rule, int rule_len) {
    if (path_len < rule_len) return FALSE;
    if (_wcsnicmp(path, rule, rule_len) != 0) return FALSE;
    if (path_len == rule_len) return TRUE;
    return path[rule_len] == L'\\';
}

/**
 * Normalize an NT path (e.g. \??\C:\...) to a comparable Win32 path.
 * Returns path length or 0 if path cannot be normalized.
 */
static int normalize_nt_path(const WCHAR* raw, int raw_len,
                             WCHAR* out, int out_max) {
    if (!raw || raw_len <= 0) return 0;

    const WCHAR* src = raw;
    int src_len = raw_len;

    /* Strip \??\ prefix */
    if (src_len >= 4 && src[0] == L'\\' && src[1] == L'?' &&
        src[2] == L'?' && src[3] == L'\\') {
        src += 4;
        src_len -= 4;
    }
    /* Skip ALL \Device\ paths -- these are kernel device objects, not filesystem.
     * Includes: \Device\KSecDD, \Device\Afd, \Device\NamedPipe,
     *           \Device\HarddiskVolume (can't resolve to drive letter), etc. */
    else if (src_len >= 8 && _wcsnicmp(src, L"\\Device\\", 8) == 0) {
        return 0;
    }

    if (src_len <= 0 || src_len >= out_max) return 0;

    /* Copy and normalize: lowercase, forward->backslash */
    for (int i = 0; i < src_len; i++) {
        WCHAR c = src[i];
        if (c == L'/') c = L'\\';
        if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        out[i] = c;
    }
    out[src_len] = L'\0';

    /* Strip trailing backslash unless root */
    if (src_len > 3 && out[src_len - 1] == L'\\') {
        out[src_len - 1] = L'\0';
        src_len--;
    }

    return src_len;
}

/**
 * Check file access against policy. Returns TRUE if allowed.
 * Sets *violation_type if denied.
 */
static BOOL check_access(const WCHAR* norm_path, int path_len,
                         ACCESS_MASK desired, WORD* violation_type) {
    BOOL wants_write  = (desired & WRITE_INTENT_MASK) != 0;
    BOOL wants_exec   = (desired & EXEC_INTENT_MASK) != 0;
    BOOL wants_delete = (desired & DELETE_INTENT_MASK) != 0;

    int best_idx = -1;
    int best_len = 0;

    for (int i = 0; i < g_policy.rule_count; i++) {
        POLICY_RULE* rule = &g_policy.rules[i];
        if (is_subpath(norm_path, path_len, rule->path, rule->path_len)) {
            if (rule->is_deny) {
                /* Deny rules have absolute priority */
                if (wants_write) *violation_type = VIOLATION_WRITE;
                else if (wants_delete) *violation_type = VIOLATION_DELETE;
                else if (wants_exec) *violation_type = VIOLATION_EXECUTE;
                else *violation_type = VIOLATION_READ;
                return FALSE;
            }
            if (rule->path_len > best_len) {
                best_len = rule->path_len;
                best_idx = i;
            }
        }
    }

    /* Apply best matching allow rule */
    if (best_idx >= 0) {
        BYTE allowed = g_policy.rules[best_idx].access;
        if (wants_write && !(allowed & ACCESS_WRITE)) {
            *violation_type = VIOLATION_WRITE;
            return FALSE;
        }
        if (wants_delete && !(allowed & ACCESS_WRITE)) {
            *violation_type = VIOLATION_DELETE;
            return FALSE;
        }
        if (wants_exec && !(allowed & ACCESS_EXECUTE)) {
            *violation_type = VIOLATION_EXECUTE;
            return FALSE;
        }
        return TRUE;
    }

    /* Default policy */
    if (g_policy.allow_read_all) {
        if (wants_write || wants_delete) {
            *violation_type = VIOLATION_WRITE;
            return FALSE;
        }
        return TRUE;
    }

    /* Strict mode: deny everything not explicitly allowed */
    *violation_type = wants_write ? VIOLATION_WRITE : VIOLATION_READ;
    return FALSE;
}

/* ===========================================================================
 * Violation logging (to shared memory ring buffer)
 * =========================================================================== */

static void log_violation(const WCHAR* path, int path_len, WORD access_type) {
    if (!g_shm_view) return;

    SANDBOX_POLICY_HEADER* hdr = (SANDBOX_POLICY_HEADER*)g_shm_view;
    DWORD log_offset = hdr->violation_log_offset;
    DWORD log_size = hdr->violation_log_size;

    DWORD path_bytes = (DWORD)(path_len * sizeof(WCHAR));
    DWORD entry_size = (DWORD)(VIOLATION_ENTRY_HDR_SIZE + path_bytes);

    if (entry_size > log_size) return;

    /* Get write position (simple atomic) */
    DWORD write_pos = InterlockedCompareExchange(
        (volatile LONG*)&hdr->violation_write_pos, 0, 0);
    write_pos = write_pos % log_size;

    if (write_pos + entry_size > log_size) {
        write_pos = 0;
    }

    /* Build entry */
    BYTE* base = (BYTE*)g_shm_view + log_offset + write_pos;
    VIOLATION_ENTRY* entry = (VIOLATION_ENTRY*)base;
    entry->total_size = entry_size;
    entry->timestamp = GetTickCount();
    entry->pid = GetCurrentProcessId();
    entry->tid = GetCurrentThreadId();
    entry->path_length = (WORD)path_len;
    entry->access_type = access_type;

    memcpy(base + VIOLATION_ENTRY_HDR_SIZE, path, path_bytes);

    /* Update write position and count */
    InterlockedExchange((volatile LONG*)&hdr->violation_write_pos,
                        (LONG)(write_pos + entry_size));
    InterlockedIncrement((volatile LONG*)&hdr->violation_count);
}

/* ===========================================================================
 * Inline hook engine (x64 E9 relay)
 * =========================================================================== */

/**
 * Minimal x64 instruction length decoder for function prologues.
 * Returns length of instruction at code[0], or 0 if unknown.
 */
static int x64_insn_length(const BYTE* code) {
    const BYTE* p = code;
    BOOL has_rex = FALSE;
    BOOL rex_w = FALSE;

    /* Skip prefixes */
    while (1) {
        if (*p >= 0x40 && *p <= 0x4F) { has_rex = TRUE; rex_w = (*p & 0x08) != 0; p++; }
        else if (*p == 0x66 || *p == 0x67) { p++; }
        else break;
    }

    BYTE opcode = *p++;

    /* PUSH/POP reg */
    if (opcode >= 0x50 && opcode <= 0x5F) return (int)(p - code);
    /* RET, NOP, INT3 */
    if (opcode == 0xC3 || opcode == 0x90 || opcode == 0xCC) return (int)(p - code);
    /* MOV reg, imm32/imm64 */
    if (opcode >= 0xB8 && opcode <= 0xBF) return (int)(p - code) + (rex_w ? 8 : 4);
    /* Jcc short */
    if (opcode >= 0x70 && opcode <= 0x7F) return (int)(p - code) + 1;
    /* JMP short */
    if (opcode == 0xEB) return (int)(p - code) + 1;
    /* JMP/CALL rel32 */
    if (opcode == 0xE9 || opcode == 0xE8) return (int)(p - code) + 4;

    /* Two-byte opcode 0F xx */
    if (opcode == 0x0F) {
        BYTE op2 = *p++;
        if (op2 == 0x05) return (int)(p - code);  /* SYSCALL */
        if (op2 >= 0x80 && op2 <= 0x8F) return (int)(p - code) + 4;  /* Jcc near */
        return 0;
    }

    /* ModRM-based opcodes */
    static const BYTE modrm_ops[] = {
        0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B,
        0x31, 0x33, 0x39, 0x3B, 0x63, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0
    };
    BOOL is_modrm = FALSE;
    for (int i = 0; modrm_ops[i]; i++) {
        if (opcode == modrm_ops[i]) { is_modrm = TRUE; break; }
    }

    /* Group opcodes */
    BOOL is_group = (opcode == 0x80 || opcode == 0x81 || opcode == 0x83 ||
                     opcode == 0xC7 || opcode == 0xF6 || opcode == 0xF7);

    if (is_modrm || is_group) {
        BYTE modrm = *p++;
        BYTE mod = (modrm >> 6) & 3;
        BYTE rm  = modrm & 7;

        if (mod != 3 && rm == 4) p++;  /* SIB byte */
        if (mod == 1) p += 1;          /* disp8 */
        else if (mod == 2) p += 4;     /* disp32 */
        else if (mod == 0 && rm == 5) p += 4; /* RIP-rel disp32 */

        /* Immediate for group opcodes */
        if (is_group) {
            BYTE reg_op = (modrm >> 3) & 7;
            if (opcode == 0x80) p += 1;
            else if (opcode == 0x81) p += 4;
            else if (opcode == 0x83) p += 1;
            else if (opcode == 0xC7) p += 4;
            else if (opcode == 0xF6 && reg_op <= 1) p += 1;
            else if (opcode == 0xF7 && reg_op <= 1) p += 4;
        }

        return (int)(p - code);
    }

    return 0;
}

/**
 * Calculate minimum bytes to copy for trampoline (instruction-aligned >= 5).
 */
static int calc_trampoline_copy_size(const BYTE* code) {
    int total = 0;
    while (total < 5) {
        int len = x64_insn_length(code + total);
        if (len == 0) return 0;
        total += len;
    }
    return total;
}

/**
 * Allocate executable memory near target (within +/-2GB for E9 rel32).
 */
static BYTE* alloc_near(void* target, SIZE_T size) {
    ULONG_PTR base = (ULONG_PTR)target;
    DWORD granularity = 0x10000;  /* 64KB */

    for (int step = 1; step < 0x7FFF; step++) {
        for (int dir = -1; dir <= 1; dir += 2) {
            ULONG_PTR candidate = base + (ULONG_PTR)(dir * step * granularity);
            candidate &= ~((ULONG_PTR)granularity - 1);
            if (candidate == 0 || candidate > 0x7FFFFFFFFFFF) continue;

            BYTE* addr = (BYTE*)VirtualAlloc(
                (LPVOID)candidate, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr) {
                LONGLONG diff = (LONGLONG)addr - (LONGLONG)((BYTE*)target + 5);
                if (diff >= -0x80000000LL && diff < 0x7FFFFFFFLL) {
                    return addr;
                }
                VirtualFree(addr, 0, MEM_RELEASE);
            }
        }
    }
    return NULL;
}

/**
 * Install a single inline hook.
 * Returns the trampoline pointer (callable as original function) or NULL.
 */
static BYTE* install_hook(void* target, void* detour, BYTE* trampoline_buf) {
    BYTE* func = (BYTE*)target;

    /* Handle existing E9 hook (AV/EDR) */
    if (func[0] == 0xE9) {
        INT32 rel32;
        memcpy(&rel32, func + 1, 4);
        BYTE* third_party = func + 5 + rel32;

        /* Trampoline: absolute JMP to third-party target */
        trampoline_buf[0] = 0xFF;
        trampoline_buf[1] = 0x25;
        *(DWORD*)(trampoline_buf + 2) = 0;
        *(UINT64*)(trampoline_buf + 6) = (UINT64)third_party;
    } else {
        /* Standard: copy prologue + JMP back */
        int copy_size = calc_trampoline_copy_size(func);
        if (copy_size == 0) return NULL;

        memcpy(trampoline_buf, func, copy_size);
        /* Absolute JMP back to func + copy_size */
        trampoline_buf[copy_size] = 0xFF;
        trampoline_buf[copy_size + 1] = 0x25;
        *(DWORD*)(trampoline_buf + copy_size + 2) = 0;
        *(UINT64*)(trampoline_buf + copy_size + 6) = (UINT64)(func + copy_size);
    }

    /* Allocate relay near target for E9 */
    BYTE* relay = alloc_near(target, 64);
    if (!relay) return NULL;

    /* Relay: absolute JMP to detour */
    relay[0] = 0xFF;
    relay[1] = 0x25;
    *(DWORD*)(relay + 2) = 0;
    *(UINT64*)(relay + 6) = (UINT64)detour;

    /* Patch target: E9 rel32 -> relay */
    DWORD old_prot;
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &old_prot);

    INT32 disp = (INT32)((BYTE*)relay - (func + 5));
    func[0] = 0xE9;
    memcpy(func + 1, &disp, 4);

    VirtualProtect(func, 5, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), func, 5);

    return trampoline_buf;
}

/* ===========================================================================
 * Hook callbacks
 * =========================================================================== */

/**
 * Extract file path from OBJECT_ATTRIBUTES and check access.
 * Returns STATUS_ACCESS_DENIED if blocked, or calls original otherwise.
 */
static NTSTATUS check_file_op(POBJECT_ATTRIBUTES obj_attr, ACCESS_MASK desired) {
    if (!obj_attr || !obj_attr->ObjectName) return STATUS_SUCCESS;

    UNICODE_STRING* ustr = obj_attr->ObjectName;
    if (!ustr->Buffer || ustr->Length == 0) return STATUS_SUCCESS;

    int wchar_count = ustr->Length / sizeof(WCHAR);

    /* Network blocking: deny socket creation when deny_network is set.
     * All TCP/UDP sockets go through NtCreateFile("\Device\Afd\...").
     * Note: ICMP (ping) uses IcmpSendEcho2 via iphlpapi.dll which bypasses
     * user-mode NtCreateFile entirely, so it cannot be blocked here. */
    if (g_policy.deny_network) {
        const WCHAR* p = ustr->Buffer;
        int off = 0;
        /* Skip \??\ prefix if present */
        if (wchar_count >= 4 && p[0]==L'\\' && p[1]==L'?' && p[2]==L'?' && p[3]==L'\\')
            off = 4;
        int remain = wchar_count - off;
        if (remain >= 11 && _wcsnicmp(p + off, L"\\Device\\Afd", 11) == 0) {
            DBG("NETWORK DENIED: %.*ls", wchar_count, p);
            log_violation(L"<network>", 9, VIOLATION_NETWORK);
            return (NTSTATUS)0xC0000022L;  /* STATUS_ACCESS_DENIED */
        }
    }

    WCHAR norm_path[MAX_PATH_LENGTH];

    int norm_len = normalize_nt_path(ustr->Buffer, wchar_count,
                                     norm_path, MAX_PATH_LENGTH);
    if (norm_len == 0) return STATUS_SUCCESS;  /* Can't normalize -> allow */

    /* Only enforce policy on paths with a drive letter (e.g., "c:\...").
     * Non-filesystem paths (pipes, devices, etc.) that slipped through
     * normalize_nt_path should be allowed unconditionally. */
    if (norm_len < 3 || norm_path[1] != L':' || norm_path[2] != L'\\') {
        return STATUS_SUCCESS;
    }

    WORD violation_type = 0;
    if (!check_access(norm_path, norm_len, desired, &violation_type)) {
        DBG("DENIED: %ls (access=0x%08X, vtype=%d)", norm_path, desired, violation_type);
        log_violation(norm_path, norm_len, violation_type);
        return (NTSTATUS)0xC0000022L;  /* STATUS_ACCESS_DENIED */
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI hooked_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    NTSTATUS status = check_file_op(ObjectAttributes, DesiredAccess);
    if (status != STATUS_SUCCESS) return status;

    return g_orig_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

static NTSTATUS NTAPI hooked_NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    NTSTATUS status = check_file_op(ObjectAttributes, DesiredAccess);
    if (status != STATUS_SUCCESS) return status;

    return g_orig_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, ShareAccess, OpenOptions);
}

static NTSTATUS NTAPI hooked_NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS status = check_file_op(ObjectAttributes, DELETE);
    if (status != STATUS_SUCCESS) return status;

    return g_orig_NtDeleteFile(ObjectAttributes);
}

/**
 * Hook NtFsControlFile to block symlink/junction creation.
 * FSCTL_SET_REPARSE_POINT is the ioctl used by mklink /D, mklink /J, and
 * CreateSymbolicLink(). Blocking this prevents symlink-based sandbox escapes
 * where a link inside an allowed directory points to a denied path.
 */
static NTSTATUS NTAPI hooked_NtFsControlFile(
    HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength)
{
    if (FsControlCode == FSCTL_SET_REPARSE_POINT) {
        DBG("SYMLINK DENIED: FSCTL_SET_REPARSE_POINT blocked");
        log_violation(L"<symlink>", 9, VIOLATION_SYMLINK);
        return (NTSTATUS)0xC0000022L;  /* STATUS_ACCESS_DENIED */
    }

    return g_orig_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);
}

/* ===========================================================================
 * DLL injection into child process
 * =========================================================================== */

/**
 * Inject this DLL into a suspended process.
 * Uses CreateRemoteThread + LoadLibraryW.
 */
static BOOL inject_dll_into_process(HANDLE hProcess, HANDLE hThread) {
    SIZE_T path_size = (wcslen(g_dll_path) + 1) * sizeof(WCHAR);

    /* Allocate memory in target for DLL path string */
    LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, path_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remote_buf) {
        DBG("VirtualAllocEx failed: %u", GetLastError());
        return FALSE;
    }

    /* Write DLL path to target process */
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remote_buf, g_dll_path, path_size, &written)) {
        DBG("WriteProcessMemory failed: %u", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Get LoadLibraryW address (same in all processes due to ASLR consistency) */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        DBG("GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Create remote thread calling LoadLibraryW(dll_path) */
    HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, remote_buf, 0, NULL);
    if (!hRemote) {
        DBG("CreateRemoteThread failed: %u", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Wait for DLL to load (with timeout) */
    WaitForSingleObject(hRemote, 5000);
    CloseHandle(hRemote);

    /* Free the remote buffer (DLL path is no longer needed) */
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);

    DBG("DLL injected successfully into PID %u", GetProcessId(hProcess));
    return TRUE;
}

/* ===========================================================================
 * CreateProcess hooks (inject DLL into children)
 * =========================================================================== */

static BOOL WINAPI hooked_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    DBG("CreateProcessW: %ls", lpCommandLine ? lpCommandLine : L"(null)");

    /* Add CREATE_SUSPENDED so we can inject before the process runs */
    BOOL was_suspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    dwCreationFlags |= CREATE_SUSPENDED;

    BOOL result = g_orig_CreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        /* Inject our DLL into the child process */
        inject_dll_into_process(lpProcessInformation->hProcess,
                               lpProcessInformation->hThread);

        /* Resume the child's main thread if it wasn't originally suspended */
        if (!was_suspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

static BOOL WINAPI hooked_CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    DBG("CreateProcessA: %s", lpCommandLine ? lpCommandLine : "(null)");

    BOOL was_suspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    dwCreationFlags |= CREATE_SUSPENDED;

    BOOL result = g_orig_CreateProcessA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        inject_dll_into_process(lpProcessInformation->hProcess,
                               lpProcessInformation->hThread);

        if (!was_suspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

/* ===========================================================================
 * Hook installation / removal
 * =========================================================================== */

static BOOL install_all_hooks(void) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!hNtdll || !hKernel32) {
        DBG("Failed to get module handles");
        return FALSE;
    }

    /* Allocate trampolines (RWX) */
    g_tramp_NtCreateFile = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_tramp_NtOpenFile = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_tramp_NtDeleteFile = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_tramp_NtFsControlFile = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_tramp_CreateProcessW = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    g_tramp_CreateProcessA = (BYTE*)VirtualAlloc(NULL, TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!g_tramp_NtCreateFile || !g_tramp_NtOpenFile || !g_tramp_NtDeleteFile ||
        !g_tramp_NtFsControlFile || !g_tramp_CreateProcessW || !g_tramp_CreateProcessA) {
        DBG("Failed to allocate trampolines");
        return FALSE;
    }

    /* Resolve function addresses */
    FARPROC pNtCreateFile = GetProcAddress(hNtdll, "NtCreateFile");
    FARPROC pNtOpenFile = GetProcAddress(hNtdll, "NtOpenFile");
    FARPROC pNtDeleteFile = GetProcAddress(hNtdll, "NtDeleteFile");
    FARPROC pNtFsControlFile = GetProcAddress(hNtdll, "NtFsControlFile");
    FARPROC pCreateProcessW = GetProcAddress(hKernel32, "CreateProcessW");
    FARPROC pCreateProcessA = GetProcAddress(hKernel32, "CreateProcessA");

    int hook_count = 0;

    if (pNtCreateFile) {
        BYTE* t = install_hook(pNtCreateFile, hooked_NtCreateFile, g_tramp_NtCreateFile);
        if (t) { g_orig_NtCreateFile = (PFN_NtCreateFile)t; hook_count++; }
    }
    if (pNtOpenFile) {
        BYTE* t = install_hook(pNtOpenFile, hooked_NtOpenFile, g_tramp_NtOpenFile);
        if (t) { g_orig_NtOpenFile = (PFN_NtOpenFile)t; hook_count++; }
    }
    if (pNtDeleteFile) {
        BYTE* t = install_hook(pNtDeleteFile, hooked_NtDeleteFile, g_tramp_NtDeleteFile);
        if (t) { g_orig_NtDeleteFile = (PFN_NtDeleteFile)t; hook_count++; }
    }
    if (pNtFsControlFile) {
        BYTE* t = install_hook(pNtFsControlFile, hooked_NtFsControlFile, g_tramp_NtFsControlFile);
        if (t) { g_orig_NtFsControlFile = (PFN_NtFsControlFile)t; hook_count++; }
    }
    if (pCreateProcessW) {
        BYTE* t = install_hook(pCreateProcessW, hooked_CreateProcessW, g_tramp_CreateProcessW);
        if (t) { g_orig_CreateProcessW = (PFN_CreateProcessW)t; hook_count++; }
    }
    if (pCreateProcessA) {
        BYTE* t = install_hook(pCreateProcessA, hooked_CreateProcessA, g_tramp_CreateProcessA);
        if (t) { g_orig_CreateProcessA = (PFN_CreateProcessA)t; hook_count++; }
    }

    DBG("Installed %d/6 hooks", hook_count);
    g_hooks_installed = (hook_count > 0);
    return g_hooks_installed;
}

/* ===========================================================================
 * Shared memory initialization
 * =========================================================================== */

static BOOL init_shared_memory(void) {
    /* Get session ID from environment */
    DWORD len = GetEnvironmentVariableW(SANDBOX_ENV_VAR, g_session_id, 64);
    if (len == 0 || len >= 64) {
        DBG("No session ID in environment");
        return FALSE;
    }

    /* Get DLL path from environment (for child injection) */
    DWORD dll_len = GetEnvironmentVariableW(SANDBOX_DLL_PATH_VAR, g_dll_path, MAX_PATH);
    if (dll_len == 0 || dll_len >= MAX_PATH) {
        /* Fallback: get our own module path */
        GetModuleFileNameW(NULL, g_dll_path, MAX_PATH);  /* Will be overwritten below */
    }

    /* Check debug flag */
    WCHAR dbg_buf[8];
    if (GetEnvironmentVariableW(L"QWENPAW_HOOK_DEBUG", dbg_buf, 8) > 0) {
        g_debug = TRUE;
    }

    /* Open shared memory */
    WCHAR shm_name[128];
    _snwprintf(shm_name, 128, L"%s%s", SANDBOX_SHM_PREFIX, g_session_id);

    g_shm_handle = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, shm_name);
    if (!g_shm_handle) {
        DBG("OpenFileMappingW failed: %u", GetLastError());
        return FALSE;
    }

    g_shm_view = MapViewOfFile(g_shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_shm_view) {
        DBG("MapViewOfFile failed: %u", GetLastError());
        CloseHandle(g_shm_handle);
        g_shm_handle = NULL;
        return FALSE;
    }

    /* Validate header */
    SANDBOX_POLICY_HEADER* hdr = (SANDBOX_POLICY_HEADER*)g_shm_view;
    if (hdr->magic != SANDBOX_MAGIC || hdr->version != SANDBOX_VERSION) {
        DBG("Shared memory header invalid: magic=0x%08X version=%u",
            hdr->magic, hdr->version);
        UnmapViewOfFile(g_shm_view);
        CloseHandle(g_shm_handle);
        g_shm_view = NULL;
        g_shm_handle = NULL;
        return FALSE;
    }

    /* Read and parse policy JSON */
    DWORD policy_len = hdr->policy_length;
    if (policy_len == 0 || policy_len > 1024 * 1024) {
        DBG("Invalid policy length: %u", policy_len);
        return FALSE;
    }

    char* policy_json = (char*)malloc(policy_len + 1);
    if (!policy_json) return FALSE;

    memcpy(policy_json, (BYTE*)g_shm_view + SANDBOX_HEADER_SIZE, policy_len);
    policy_json[policy_len] = '\0';

    BOOL ok = parse_policy_json(policy_json, &g_policy);
    free(policy_json);

    if (!ok) {
        DBG("Failed to parse policy JSON");
        return FALSE;
    }

    DBG("Policy loaded: %d rules, allow_read_all=%d, deny_network=%d",
        g_policy.rule_count, g_policy.allow_read_all, g_policy.deny_network);
    return TRUE;
}

/* ===========================================================================
 * DLL entry point
 * =========================================================================== */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        /* Store our DLL path for child process injection */
        GetModuleFileNameW(hModule, g_dll_path, MAX_PATH);

        /* Initialize: read policy from shared memory, install hooks */
        if (init_shared_memory()) {
            install_all_hooks();
        } else {
            DBG("Failed to init shared memory, hooks not installed");
        }
        break;

    case DLL_PROCESS_DETACH:
        /* Cleanup shared memory mapping */
        if (g_shm_view) {
            UnmapViewOfFile(g_shm_view);
            g_shm_view = NULL;
        }
        if (g_shm_handle) {
            CloseHandle(g_shm_handle);
            g_shm_handle = NULL;
        }
        /* Note: we don't unhook on detach because the process is exiting.
         * Unhooking during DLL_PROCESS_DETACH can cause crashes if other
         * threads are still executing hooked code. */
        break;
    }
    return TRUE;
}
