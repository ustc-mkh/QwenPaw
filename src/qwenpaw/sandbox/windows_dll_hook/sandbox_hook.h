/**
 * sandbox_hook.h - QwenPaw DLL sandbox hook header
 *
 * Shared memory protocol definitions and constants used by both the
 * Python parent process and the injected DLL.
 */

#ifndef QWENPAW_SANDBOX_HOOK_H
#define QWENPAW_SANDBOX_HOOK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * Shared memory protocol constants
 * =========================================================================== */

#define SANDBOX_MAGIC           0x51574E50  /* "QWNP" little-endian */
#define SANDBOX_VERSION         1
#define SANDBOX_HEADER_SIZE     64
#define SANDBOX_VIOLATION_LOG_SIZE (64 * 1024)  /* 64 KB */

#define SANDBOX_SHM_PREFIX      L"Local\\QwenPaw_HookPolicy_"
#define SANDBOX_ENV_VAR         L"__QWENPAW_SANDBOX_SESSION"
#define SANDBOX_DLL_PATH_VAR    L"__QWENPAW_SANDBOX_DLL_PATH"

/* Policy flags */
#define POLICY_FLAG_DENY_NETWORK    0x01
#define POLICY_FLAG_ALLOW_READ_ALL  0x02

/* ===========================================================================
 * Shared memory header layout (64 bytes, packed)
 * =========================================================================== */

#pragma pack(push, 1)
typedef struct _SANDBOX_POLICY_HEADER {
    DWORD magic;                    /* 0x51574E50 */
    DWORD version;                  /* 1 */
    DWORD policy_length;            /* Length of JSON policy in bytes */
    DWORD flags;                    /* POLICY_FLAG_* */
    DWORD violation_log_offset;     /* Offset from start to violation ring buffer */
    DWORD violation_log_size;       /* Size of violation ring buffer */
    DWORD violation_count;          /* Atomic: number of violations */
    DWORD violation_write_pos;      /* Current write position in ring buffer */
    DWORD reserved[8];             /* Pad to 64 bytes */
} SANDBOX_POLICY_HEADER;
#pragma pack(pop)

/* ===========================================================================
 * Violation entry layout
 * =========================================================================== */

#pragma pack(push, 1)
typedef struct _VIOLATION_ENTRY {
    DWORD total_size;       /* Size of this entry including path */
    DWORD commit;           /* Set to VIOLATION_COMMIT_MAGIC after full write */
    DWORD timestamp;        /* GetTickCount() */
    DWORD pid;              /* Process ID */
    DWORD tid;              /* Thread ID */
    WORD  path_length;      /* Path length in WCHARs */
    WORD  access_type;      /* VIOLATION_* flag */
    /* Followed by path_length WCHARs */
} VIOLATION_ENTRY;
#pragma pack(pop)

#define VIOLATION_ENTRY_HDR_SIZE sizeof(VIOLATION_ENTRY)
#define VIOLATION_COMMIT_MAGIC  0x564D4F43  /* "COMV" - marks entry as fully written */

/* Violation type flags */
#define VIOLATION_READ      0x0001
#define VIOLATION_WRITE     0x0002
#define VIOLATION_DELETE     0x0004
#define VIOLATION_EXECUTE   0x0008
#define VIOLATION_NETWORK   0x0010
#define VIOLATION_SYMLINK   0x0020

/* ===========================================================================
 * Access classification masks (from Windows SDK)
 * =========================================================================== */

#define WRITE_INTENT_MASK   (FILE_WRITE_DATA | FILE_APPEND_DATA | \
                             FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
                             GENERIC_WRITE)

#define EXEC_INTENT_MASK    (FILE_EXECUTE | GENERIC_EXECUTE)
#define DELETE_INTENT_MASK   (DELETE | FILE_DELETE_CHILD)

/* Policy rule access levels */
#define ACCESS_DENY         0x00
#define ACCESS_READ         0x01
#define ACCESS_WRITE        0x02
#define ACCESS_EXECUTE      0x04
#define ACCESS_READ_EXECUTE (ACCESS_READ | ACCESS_EXECUTE)
#define ACCESS_READ_WRITE   (ACCESS_READ | ACCESS_WRITE)
#define ACCESS_FULL         (ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE)

/* Maximum policy rules */
#define MAX_POLICY_RULES    128
#define MAX_PATH_LENGTH     512

/* ===========================================================================
 * Policy rule structure (parsed from JSON)
 * =========================================================================== */

typedef struct _POLICY_RULE {
    WCHAR path[MAX_PATH_LENGTH];    /* Normalized: lowercase, backslash, no trailing */
    int   path_len;                 /* wcslen(path) */
    BYTE  access;                   /* ACCESS_* bitmask; ACCESS_DENY (0x00) for deny rules */
} POLICY_RULE;

typedef struct _SANDBOX_POLICY {
    POLICY_RULE rules[MAX_POLICY_RULES];
    int         rule_count;
    BOOL        allow_read_all;
    BOOL        deny_network;
} SANDBOX_POLICY;

#ifdef __cplusplus
}
#endif

#endif /* QWENPAW_SANDBOX_HOOK_H */
