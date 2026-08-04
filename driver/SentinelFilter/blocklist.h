/*
 * blocklist.h — Portable file-path blocklist for Sentinel minifilter.
 *
 * Design (from Phase 4 review):
 *   - Keyed by NORMALIZED file path (not hash) — zero disk I/O in callbacks
 *   - All memory allocation via caller-provided alloc/free
 *   - All locking via caller-provided lock/unlock
 *   - Compiles in both kernel mode (ExAllocatePool2/SpinLock) and
 *     user mode (malloc/CriticalSection) with zero changes
 *
 * Path normalization:
 *   - Uppercase for case-insensitive comparison (NTFS is case-insensitive)
 *   - Backslash-normalized (no forward slashes)
 *   - Max path: SENTINEL_MAX_PATH (520 WCHARs = 1040 bytes)
 *
 * Thread safety: fully safe when caller provides proper lock/unlock.
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#ifndef SENTINEL_BLOCKLIST_H
#define SENTINEL_BLOCKLIST_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>
#else
/* User-mode: provide the types we need. */
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#endif

/* Maximum path length in WCHARs (including null terminator). */
#define SENTINEL_MAX_PATH 520

/* Status codes. */
#define BL_SUCCESS          0
#define BL_ERR_DUPLICATE    1
#define BL_ERR_NOT_FOUND    2
#define BL_ERR_ALLOC_FAIL   3
#define BL_ERR_PATH_TOO_LONG 4
#define BL_ERR_NULL_ARG     5

/* ----------------------------------------------------------------------- */
/* Caller-provided function pointer types                                  */
/* ----------------------------------------------------------------------- */

/* Memory allocation: allocate `size` bytes, return pointer or NULL. */
typedef void* (*bl_alloc_fn)(void *alloc_ctx, size_t size);

/* Memory free. */
typedef void (*bl_free_fn)(void *alloc_ctx, void *ptr);

/* Acquire exclusive lock. */
typedef void (*bl_lock_fn)(void *lock_ctx);

/* Release exclusive lock. */
typedef void (*bl_unlock_fn)(void *lock_ctx);

/* ----------------------------------------------------------------------- */
/* Blocklist entry (internal)                                              */
/* ----------------------------------------------------------------------- */

typedef struct _BL_ENTRY {
    WCHAR path[SENTINEL_MAX_PATH];   /* Normalized, uppercase, null-term. */
    struct _BL_ENTRY *next;          /* Singly-linked list (sorted).      */
} BL_ENTRY;

/* ----------------------------------------------------------------------- */
/* Blocklist handle                                                        */
/* ----------------------------------------------------------------------- */

typedef struct _BLOCKLIST {
    BL_ENTRY    *head;         /* Sorted linked list of blocked paths.  */
    unsigned int count;        /* Number of entries.                    */

    /* Caller-provided hooks. */
    bl_alloc_fn  alloc;
    bl_free_fn   free_fn;      /* 'free' conflicts with stdlib.        */
    void        *alloc_ctx;

    bl_lock_fn   lock;
    bl_unlock_fn unlock;
    void        *lock_ctx;
} BLOCKLIST;

/* ----------------------------------------------------------------------- */
/* Public API                                                              */
/* ----------------------------------------------------------------------- */

/*
 * Initialize a blocklist.  All function pointers are required (non-NULL).
 * Returns BL_SUCCESS or BL_ERR_NULL_ARG.
 */
int blocklist_init(
    BLOCKLIST   *bl,
    bl_alloc_fn  alloc_fn,
    bl_free_fn   free_fn,
    void        *alloc_ctx,
    bl_lock_fn   lock_fn,
    bl_unlock_fn unlock_fn,
    void        *lock_ctx
);

/*
 * Destroy a blocklist, freeing all entries via the provided free_fn.
 * The BLOCKLIST struct itself is NOT freed (caller owns it).
 */
void blocklist_destroy(BLOCKLIST *bl);

/*
 * Add a path to the blocklist.
 * The path is normalized (uppercased, backslash-normalized) before storage.
 * Returns BL_SUCCESS, BL_ERR_DUPLICATE, BL_ERR_ALLOC_FAIL, or
 * BL_ERR_PATH_TOO_LONG.
 * Thread-safe: acquires lock internally.
 */
int blocklist_add(BLOCKLIST *bl, const WCHAR *path);

/*
 * Remove a path from the blocklist.
 * Returns BL_SUCCESS or BL_ERR_NOT_FOUND.
 * Thread-safe: acquires lock internally.
 */
int blocklist_remove(BLOCKLIST *bl, const WCHAR *path);

/*
 * Check if a path is on the blocklist.
 * Returns 1 (blocked) or 0 (not blocked).
 * Thread-safe: acquires lock internally.
 * This is the HOT PATH called from SfPreCreate — must be fast.
 */
int blocklist_contains(BLOCKLIST *bl, const WCHAR *path);

/*
 * Return current entry count.  Thread-safe.
 */
unsigned int blocklist_count(BLOCKLIST *bl);

/* ----------------------------------------------------------------------- */
/* Internal helpers (exposed for testing only)                             */
/* ----------------------------------------------------------------------- */

/*
 * Normalize a path in-place: uppercase + backslash.
 * `dst` must be at least SENTINEL_MAX_PATH WCHARs.
 * Returns BL_SUCCESS or BL_ERR_PATH_TOO_LONG.
 */
int bl_normalize_path(WCHAR *dst, const WCHAR *src);

#endif /* SENTINEL_BLOCKLIST_H */
