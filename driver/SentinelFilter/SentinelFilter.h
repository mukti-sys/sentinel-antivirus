/*
 * SentinelFilter.h — Shared structures between kernel driver and user-mode.
 *
 * Both driver/SentinelFilter/SentinelFilter.c and sentinel/kernel/messages.py
 * must agree on these definitions.
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#ifndef SENTINEL_FILTER_H
#define SENTINEL_FILTER_H

/* Communication port name. User-mode connects with this. */
#define SENTINEL_PORT_NAME L"\\SentinelFilterPort"

/* Maximum path length in WCHARs (must match blocklist.h). */
#ifndef SENTINEL_MAX_PATH
#define SENTINEL_MAX_PATH 520
#endif

/* ----------------------------------------------------------------------- */
/* Message types                                                           */
/* ----------------------------------------------------------------------- */

/* User-mode → Kernel (via FilterSendMessage) */
#define MSG_ADD_BLOCK       1  /* Add a path to the blocklist.           */
#define MSG_REMOVE_BLOCK    2  /* Remove a path from the blocklist.      */
#define MSG_QUERY_STATUS    3  /* Request current blocklist count/status. */

/* Kernel → User-mode (via FltSendMessage) */
#define MSG_BLOCK_EVENT     10 /* A file access was blocked.             */

/* ----------------------------------------------------------------------- */
/* Message structures                                                      */
/*                                                                         */
/* Fixed-size for simplicity and safety in kernel ↔ user communication.    */
/* All messages are prefixed with a ULONG type field.                      */
/* ----------------------------------------------------------------------- */

/*
 * SENTINEL_COMMAND — user-mode → kernel.
 * Used for MSG_ADD_BLOCK, MSG_REMOVE_BLOCK, MSG_QUERY_STATUS.
 */
typedef struct _SENTINEL_COMMAND {
    ULONG type;                      /* MSG_ADD_BLOCK, etc.              */
    WCHAR path[SENTINEL_MAX_PATH];   /* File path (for add/remove).     */
} SENTINEL_COMMAND;

/*
 * SENTINEL_REPLY — kernel → user-mode reply to MSG_QUERY_STATUS.
 */
typedef struct _SENTINEL_REPLY {
    ULONG status;          /* 0 = success, nonzero = error code.         */
    ULONG blocklist_count; /* Current number of entries in blocklist.    */
    ULONG blocks_total;    /* Total blocks since driver load.            */
} SENTINEL_REPLY;

/*
 * SENTINEL_BLOCK_EVENT — kernel → user-mode notification.
 * Sent when the minifilter blocks a file access.
 */
typedef struct _SENTINEL_BLOCK_EVENT {
    ULONG type;                      /* Always MSG_BLOCK_EVENT.          */
    WCHAR path[SENTINEL_MAX_PATH];   /* Blocked file path.              */
    ULONG pid;                       /* Process that tried to access.   */
    ULONG tid;                       /* Thread ID.                      */
    LARGE_INTEGER timestamp;         /* System time of the block.       */
} SENTINEL_BLOCK_EVENT;

/* Pool tag for memory allocations. 'SeFi' = Sentinel Filter. */
#define SENTINEL_POOL_TAG 'iFes'

#endif /* SENTINEL_FILTER_H */
