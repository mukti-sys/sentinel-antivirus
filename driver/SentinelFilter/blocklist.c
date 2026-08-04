/*
 * blocklist.c — Portable file-path blocklist implementation.
 *
 * Sorted singly-linked list keyed by normalized (uppercase, backslash) path.
 * Chosen over AVL tree for simplicity in v1 — the blocklist is typically
 * small (tens of entries, not thousands), so O(n) traversal is fine.
 * If profiling shows this is a bottleneck, swap to AVL without changing
 * the public API.
 *
 * Thread safety: every public function acquires the caller-provided lock.
 * The lock granularity is coarse (one lock per blocklist) which is correct
 * for a minifilter pre-create callback where the critical section is a
 * fast string comparison.
 *
 * ZERO disk I/O in any function.  This code is safe to call from
 * IRP_MJ_CREATE pre-callbacks at any IRQL <= DISPATCH_LEVEL when used
 * with a spinlock.
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#include "blocklist.h"

/* ----------------------------------------------------------------------- */
/* Path normalization                                                      */
/* ----------------------------------------------------------------------- */

/*
 * Normalize a path: uppercase every character, convert '/' to '\\'.
 * Does NOT resolve symlinks or junctions (that would require I/O).
 */
int bl_normalize_path(WCHAR *dst, const WCHAR *src)
{
    size_t i;

    if (!dst || !src) return BL_ERR_NULL_ARG;

    for (i = 0; i < SENTINEL_MAX_PATH - 1; i++) {
        WCHAR ch = src[i];
        if (ch == L'\0') break;

        /* Uppercase: ASCII range only for performance.
         * Full Unicode case-folding is not needed for NTFS paths. */
        if (ch >= L'a' && ch <= L'z')
            ch = ch - L'a' + L'A';

        /* Normalize forward slash to backslash. */
        if (ch == L'/')
            ch = L'\\';

        dst[i] = ch;
    }

    if (i >= SENTINEL_MAX_PATH - 1 && src[i] != L'\0')
        return BL_ERR_PATH_TOO_LONG;

    dst[i] = L'\0';
    return BL_SUCCESS;
}

/* ----------------------------------------------------------------------- */
/* Internal: compare two normalized paths.                                 */
/* Returns <0, 0, or >0 (like wcscmp).                                    */
/* ----------------------------------------------------------------------- */

static int bl_compare(const WCHAR *a, const WCHAR *b)
{
    /* Both are already normalized (uppercase), so direct compare is correct. */
    size_t i;
    for (i = 0; i < SENTINEL_MAX_PATH; i++) {
        if (a[i] != b[i])
            return (int)a[i] - (int)b[i];
        if (a[i] == L'\0')
            return 0;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Public API                                                              */
/* ----------------------------------------------------------------------- */

int blocklist_init(
    BLOCKLIST   *bl,
    bl_alloc_fn  alloc_fn,
    bl_free_fn   free_fn,
    void        *alloc_ctx,
    bl_lock_fn   lock_fn,
    bl_unlock_fn unlock_fn,
    void        *lock_ctx)
{
    if (!bl || !alloc_fn || !free_fn || !lock_fn || !unlock_fn)
        return BL_ERR_NULL_ARG;

    bl->head      = NULL;
    bl->count     = 0;
    bl->alloc     = alloc_fn;
    bl->free_fn   = free_fn;
    bl->alloc_ctx = alloc_ctx;
    bl->lock      = lock_fn;
    bl->unlock    = unlock_fn;
    bl->lock_ctx  = lock_ctx;

    return BL_SUCCESS;
}

void blocklist_destroy(BLOCKLIST *bl)
{
    BL_ENTRY *cur, *next;

    if (!bl) return;

    bl->lock(bl->lock_ctx);

    cur = bl->head;
    while (cur) {
        next = cur->next;
        bl->free_fn(bl->alloc_ctx, cur);
        cur = next;
    }
    bl->head  = NULL;
    bl->count = 0;

    bl->unlock(bl->lock_ctx);
}

int blocklist_add(BLOCKLIST *bl, const WCHAR *path)
{
    WCHAR normalized[SENTINEL_MAX_PATH];
    BL_ENTRY *entry, *cur, *prev;
    int cmp, rc;

    if (!bl || !path) return BL_ERR_NULL_ARG;

    rc = bl_normalize_path(normalized, path);
    if (rc != BL_SUCCESS) return rc;

    bl->lock(bl->lock_ctx);

    /* Walk the sorted list to find the insert point. */
    prev = NULL;
    cur  = bl->head;
    while (cur) {
        cmp = bl_compare(normalized, cur->path);
        if (cmp == 0) {
            /* Duplicate. */
            bl->unlock(bl->lock_ctx);
            return BL_ERR_DUPLICATE;
        }
        if (cmp < 0)
            break;  /* Insert before cur. */
        prev = cur;
        cur  = cur->next;
    }

    /* Allocate new entry. */
    entry = (BL_ENTRY *)bl->alloc(bl->alloc_ctx, sizeof(BL_ENTRY));
    if (!entry) {
        bl->unlock(bl->lock_ctx);
        return BL_ERR_ALLOC_FAIL;
    }

    /* Copy normalized path. */
    memcpy(entry->path, normalized, sizeof(normalized));
    entry->next = cur;

    /* Link into list. */
    if (prev)
        prev->next = entry;
    else
        bl->head = entry;

    bl->count++;
    bl->unlock(bl->lock_ctx);
    return BL_SUCCESS;
}

int blocklist_remove(BLOCKLIST *bl, const WCHAR *path)
{
    WCHAR normalized[SENTINEL_MAX_PATH];
    BL_ENTRY *cur, *prev;
    int cmp, rc;

    if (!bl || !path) return BL_ERR_NULL_ARG;

    rc = bl_normalize_path(normalized, path);
    if (rc != BL_SUCCESS) return rc;

    bl->lock(bl->lock_ctx);

    prev = NULL;
    cur  = bl->head;
    while (cur) {
        cmp = bl_compare(normalized, cur->path);
        if (cmp == 0) {
            /* Found — unlink and free. */
            if (prev)
                prev->next = cur->next;
            else
                bl->head = cur->next;

            bl->free_fn(bl->alloc_ctx, cur);
            bl->count--;
            bl->unlock(bl->lock_ctx);
            return BL_SUCCESS;
        }
        if (cmp < 0)
            break;  /* Past the sorted position — not found. */
        prev = cur;
        cur  = cur->next;
    }

    bl->unlock(bl->lock_ctx);
    return BL_ERR_NOT_FOUND;
}

int blocklist_contains(BLOCKLIST *bl, const WCHAR *path)
{
    WCHAR normalized[SENTINEL_MAX_PATH];
    BL_ENTRY *cur;
    int cmp, rc;

    if (!bl || !path) return 0;

    rc = bl_normalize_path(normalized, path);
    if (rc != BL_SUCCESS) return 0;

    bl->lock(bl->lock_ctx);

    cur = bl->head;
    while (cur) {
        cmp = bl_compare(normalized, cur->path);
        if (cmp == 0) {
            bl->unlock(bl->lock_ctx);
            return 1;  /* BLOCKED */
        }
        if (cmp < 0)
            break;  /* Past sorted position. */
        cur = cur->next;
    }

    bl->unlock(bl->lock_ctx);
    return 0;  /* NOT BLOCKED */
}

unsigned int blocklist_count(BLOCKLIST *bl)
{
    unsigned int n;
    if (!bl) return 0;

    bl->lock(bl->lock_ctx);
    n = bl->count;
    bl->unlock(bl->lock_ctx);
    return n;
}
