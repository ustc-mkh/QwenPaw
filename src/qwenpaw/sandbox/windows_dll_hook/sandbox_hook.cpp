/**
 * sandbox_hook.cpp - QwenPaw DLL-based sandbox hook implementation
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
 * Dependencies: Microsoft Detours (hooking), cJSON (policy parsing)
 * Build: cmake with vcpkg toolchain (see build.bat)
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <detours/detours.h>
#include <cjson/cJSON.h>

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

/* Original function pointers -- populated by DetourAttach */
static PFN_NtCreateFile    g_orig_NtCreateFile = NULL;
static PFN_NtOpenFile      g_orig_NtOpenFile = NULL;
static PFN_NtDeleteFile    g_orig_NtDeleteFile = NULL;
static PFN_NtFsControlFile g_orig_NtFsControlFile = NULL;
static PFN_CreateProcessW  g_orig_CreateProcessW = NULL;
static PFN_CreateProcessA  g_orig_CreateProcessA = NULL;

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
 * Policy JSON parsing (cJSON)
 * =========================================================================== */

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

    cJSON* root = cJSON_Parse(json);
    if (!root) {
        DBG("cJSON_Parse failed: %s",
            cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown");
        return FALSE;
    }

    cJSON* allow_read_all = cJSON_GetObjectItemCaseSensitive(root, "allow_read_all");
    if (cJSON_IsBool(allow_read_all)) {
        policy->allow_read_all = cJSON_IsTrue(allow_read_all);
    }

    cJSON* deny_network = cJSON_GetObjectItemCaseSensitive(root, "deny_network");
    if (cJSON_IsBool(deny_network)) {
        policy->deny_network = cJSON_IsTrue(deny_network);
    }

    cJSON* rules = cJSON_GetObjectItemCaseSensitive(root, "rules");
    if (cJSON_IsArray(rules)) {
        cJSON* rule_item = NULL;
        cJSON_ArrayForEach(rule_item, rules) {
            if (policy->rule_count >= MAX_POLICY_RULES) break;

            cJSON* path_item = cJSON_GetObjectItemCaseSensitive(rule_item, "path");
            cJSON* access_item = cJSON_GetObjectItemCaseSensitive(rule_item, "access");

            if (!cJSON_IsString(path_item) || !path_item->valuestring[0])
                continue;

            POLICY_RULE* rule = &policy->rules[policy->rule_count];

            normalize_path_to_wchar(path_item->valuestring, rule->path, MAX_PATH_LENGTH);
            rule->path_len = (int)wcslen(rule->path);

            const char* access_str = cJSON_IsString(access_item)
                                         ? access_item->valuestring : "r";

            if (strcmp(access_str, "deny") == 0) {
                rule->access = ACCESS_DENY;
                rule->is_deny = 1;
            } else if (strcmp(access_str, "rw") == 0) {
                rule->access = ACCESS_FULL;
                rule->is_deny = 0;
            } else if (strcmp(access_str, "rx") == 0) {
                rule->access = ACCESS_READ_EXECUTE;
                rule->is_deny = 0;
            } else {
                rule->access = ACCESS_READ;
                rule->is_deny = 0;
            }

            policy->rule_count++;
        }
    }

    cJSON_Delete(root);
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

    /* Atomically reserve space in the ring buffer using a CAS loop.
     * This prevents the race condition where two threads read the same
     * write_pos and overwrite each other's entries. */
    LONG old_pos, new_pos;
    do {
        old_pos = InterlockedCompareExchange(
            (volatile LONG*)&hdr->violation_write_pos, 0, 0);
        new_pos = old_pos % (LONG)log_size;
        if ((DWORD)new_pos + entry_size > log_size) {
            new_pos = 0;
        }
    } while (InterlockedCompareExchange(
                 (volatile LONG*)&hdr->violation_write_pos,
                 new_pos + (LONG)entry_size,
                 old_pos) != old_pos);

    /* Build entry at reserved position */
    BYTE* base = (BYTE*)g_shm_view + log_offset + new_pos;
    VIOLATION_ENTRY* entry = (VIOLATION_ENTRY*)base;
    entry->total_size = entry_size;
    entry->timestamp = GetTickCount();
    entry->pid = GetCurrentProcessId();
    entry->tid = GetCurrentThreadId();
    entry->path_length = (WORD)path_len;
    entry->access_type = access_type;

    memcpy(base + VIOLATION_ENTRY_HDR_SIZE, path, path_bytes);

    /* Increment violation count */
    InterlockedIncrement((volatile LONG*)&hdr->violation_count);
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
 * Check if a file handle corresponds to a path with write permission.
 * Uses GetFinalPathNameByHandleW to resolve the handle to a path, then
 * checks the path against the policy.
 */
static BOOL is_handle_in_writable_dir(HANDLE hFile) {
    typedef DWORD (WINAPI *PFN_GetFinalPathNameByHandleW)(
        HANDLE, LPWSTR, DWORD, DWORD);
    static PFN_GetFinalPathNameByHandleW pfn = NULL;
    static BOOL resolved = FALSE;

    if (!resolved) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            pfn = (PFN_GetFinalPathNameByHandleW)GetProcAddress(
                hKernel32, "GetFinalPathNameByHandleW");
        }
        resolved = TRUE;
    }
    if (!pfn) return FALSE;

    WCHAR path_buf[MAX_PATH_LENGTH];
    DWORD len = pfn(hFile, path_buf, MAX_PATH_LENGTH, 0 /* VOLUME_NAME_DOS */);
    if (len == 0 || len >= MAX_PATH_LENGTH) return FALSE;

    /* Result is prefixed with "\\?\", strip it */
    WCHAR* path = path_buf;
    int path_len = (int)len;
    if (path_len >= 4 && path[0] == L'\\' && path[1] == L'\\' &&
        path[2] == L'?' && path[3] == L'\\') {
        path += 4;
        path_len -= 4;
    }

    /* Normalize to lowercase */
    WCHAR norm_path[MAX_PATH_LENGTH];
    for (int i = 0; i < path_len; i++) {
        WCHAR c = path[i];
        if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        norm_path[i] = c;
    }
    norm_path[path_len] = L'\0';

    /* Check if any writable rule covers this path */
    for (int i = 0; i < g_policy.rule_count; i++) {
        POLICY_RULE* rule = &g_policy.rules[i];
        if (rule->is_deny) continue;
        if (!(rule->access & ACCESS_WRITE)) continue;
        if (is_subpath(norm_path, path_len, rule->path, rule->path_len)) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Hook NtFsControlFile to block symlink/junction creation.
 * FSCTL_SET_REPARSE_POINT is the ioctl used by mklink /D, mklink /J, and
 * CreateSymbolicLink(). Blocking this prevents symlink-based sandbox escapes
 * where a link inside an allowed directory points to a denied path.
 *
 * Symlinks are allowed within writable directories (e.g., npm link in workspace).
 */
static NTSTATUS NTAPI hooked_NtFsControlFile(
    HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength)
{
    if (FsControlCode == FSCTL_SET_REPARSE_POINT) {
        /* Allow symlink creation within writable directories */
        if (is_handle_in_writable_dir(FileHandle)) {
            DBG("SYMLINK ALLOWED: target is in writable directory");
        } else {
            DBG("SYMLINK DENIED: FSCTL_SET_REPARSE_POINT blocked");
            log_violation(L"<symlink>", 9, VIOLATION_SYMLINK);
            return (NTSTATUS)0xC0000022L;  /* STATUS_ACCESS_DENIED */
        }
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
static BOOL inject_dll_into_process(HANDLE hProcess) {
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
        inject_dll_into_process(lpProcessInformation->hProcess);

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
        inject_dll_into_process(lpProcessInformation->hProcess);

        if (!was_suspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

/* ===========================================================================
 * Hook installation / removal (Microsoft Detours)
 * =========================================================================== */

static BOOL install_all_hooks(void) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!hNtdll || !hKernel32) {
        DBG("Failed to get module handles");
        return FALSE;
    }

    /* Resolve original function addresses */
    g_orig_NtCreateFile = (PFN_NtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    g_orig_NtOpenFile = (PFN_NtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
    g_orig_NtDeleteFile = (PFN_NtDeleteFile)GetProcAddress(hNtdll, "NtDeleteFile");
    g_orig_NtFsControlFile = (PFN_NtFsControlFile)GetProcAddress(hNtdll, "NtFsControlFile");
    g_orig_CreateProcessW = (PFN_CreateProcessW)GetProcAddress(hKernel32, "CreateProcessW");
    g_orig_CreateProcessA = (PFN_CreateProcessA)GetProcAddress(hKernel32, "CreateProcessA");

    /* Begin Detours transaction */
    DetourRestoreAfterWith();

    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        DBG("DetourTransactionBegin failed: %ld", error);
        return FALSE;
    }

    DetourUpdateThread(GetCurrentThread());

    /* Attach each hook */
    if (g_orig_NtCreateFile)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_NtCreateFile), hooked_NtCreateFile);
    if (g_orig_NtOpenFile)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_NtOpenFile), hooked_NtOpenFile);
    if (g_orig_NtDeleteFile)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_NtDeleteFile), hooked_NtDeleteFile);
    if (g_orig_NtFsControlFile)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_NtFsControlFile), hooked_NtFsControlFile);
    if (g_orig_CreateProcessW)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_CreateProcessW), hooked_CreateProcessW);
    if (g_orig_CreateProcessA)
        DetourAttach(reinterpret_cast<PVOID*>(&g_orig_CreateProcessA), hooked_CreateProcessA);

    /* Commit -- atomically patches all targets */
    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        DBG("DetourTransactionCommit failed: %ld", error);
        return FALSE;
    }

    g_hooks_installed = TRUE;
    DBG("All hooks installed via Detours");
    return TRUE;
}

static void remove_all_hooks(void) {
    if (!g_hooks_installed) return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_orig_NtCreateFile)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_NtCreateFile), hooked_NtCreateFile);
    if (g_orig_NtOpenFile)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_NtOpenFile), hooked_NtOpenFile);
    if (g_orig_NtDeleteFile)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_NtDeleteFile), hooked_NtDeleteFile);
    if (g_orig_NtFsControlFile)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_NtFsControlFile), hooked_NtFsControlFile);
    if (g_orig_CreateProcessW)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_CreateProcessW), hooked_CreateProcessW);
    if (g_orig_CreateProcessA)
        DetourDetach(reinterpret_cast<PVOID*>(&g_orig_CreateProcessA), hooked_CreateProcessA);

    DetourTransactionCommit();
    g_hooks_installed = FALSE;
    DBG("All hooks removed via Detours");
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

    /* Get DLL path from environment (for child injection).
     * If not set, g_dll_path already contains the correct path from DllMain
     * via GetModuleFileNameW(hModule, ...). */
    WCHAR env_dll_path[MAX_PATH];
    DWORD dll_len = GetEnvironmentVariableW(SANDBOX_DLL_PATH_VAR, env_dll_path, MAX_PATH);
    if (dll_len > 0 && dll_len < MAX_PATH) {
        memcpy(g_dll_path, env_dll_path, (dll_len + 1) * sizeof(WCHAR));
    }
    /* Otherwise keep g_dll_path set by DllMain (correct module path) */

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
    (void)lpReserved;

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
        /* With Detours, we can safely unhook on detach */
        remove_all_hooks();

        /* Cleanup shared memory mapping */
        if (g_shm_view) {
            UnmapViewOfFile(g_shm_view);
            g_shm_view = NULL;
        }
        if (g_shm_handle) {
            CloseHandle(g_shm_handle);
            g_shm_handle = NULL;
        }
        break;
    }
    return TRUE;
}
