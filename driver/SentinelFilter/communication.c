/*
 * communication.c — Filter communication port callbacks.
 *
 * Handles user-mode ↔ kernel-mode message passing:
 *   - User-mode → Kernel: MSG_ADD_BLOCK, MSG_REMOVE_BLOCK, MSG_QUERY_STATUS
 *   - Kernel → User-mode: MSG_BLOCK_EVENT (sent from SfPreCreate)
 *
 * Security: only one client at a time (the Sentinel service), enforced by
 * MaxConnections=1 in FltCreateCommunicationPort and DACL restricting to
 * admin/SYSTEM.
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#include <fltKernel.h>
#include "SentinelFilter.h"
#include "blocklist.h"

/* External globals from SentinelFilter.c. */
extern PFLT_FILTER  g_FilterHandle;
extern PFLT_PORT    g_ClientPort;
extern BLOCKLIST    g_Blocklist;
extern ULONG        g_TotalBlocks;

/* ----------------------------------------------------------------------- */
/* Connect callback                                                        */
/* ----------------------------------------------------------------------- */

NTSTATUS SfPortConnect(
    PFLT_PORT ClientPort,
    PVOID     ServerPortCookie,
    PVOID     ConnectionContext,
    ULONG     SizeOfContext,
    PVOID    *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    /* Store client port handle for FltSendMessage in SfPreCreate. */
    g_ClientPort = ClientPort;

    DbgPrint("[SentinelFilter] User-mode client connected\n");
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------- */
/* Disconnect callback                                                     */
/* ----------------------------------------------------------------------- */

void SfPortDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    /* Close the client port — Filter Manager handles the cleanup. */
    FltCloseClientPort(g_FilterHandle, &g_ClientPort);
    g_ClientPort = NULL;

    DbgPrint("[SentinelFilter] User-mode client disconnected\n");
}

/* ----------------------------------------------------------------------- */
/* Message callback                                                        */
/* ----------------------------------------------------------------------- */

NTSTATUS SfPortMessage(
    PVOID  PortCookie,
    PVOID  InputBuffer,
    ULONG  InputBufferLength,
    PVOID  OutputBuffer,
    ULONG  OutputBufferLength,
    PULONG ReturnOutputBufferLength)
{
    SENTINEL_COMMAND *cmd;
    int               rc;

    UNREFERENCED_PARAMETER(PortCookie);

    /* Validate input. */
    if (!InputBuffer || InputBufferLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    cmd = (SENTINEL_COMMAND *)InputBuffer;

    switch (cmd->type) {

    case MSG_ADD_BLOCK:
        if (InputBufferLength < sizeof(SENTINEL_COMMAND)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        /* Ensure null termination (safety). */
        cmd->path[SENTINEL_MAX_PATH - 1] = L'\0';

        rc = blocklist_add(&g_Blocklist, cmd->path);
        if (rc == BL_SUCCESS) {
            DbgPrint("[SentinelFilter] Blocked path added: %ws\n", cmd->path);
        } else if (rc == BL_ERR_DUPLICATE) {
            DbgPrint("[SentinelFilter] Path already blocked: %ws\n", cmd->path);
        } else {
            DbgPrint("[SentinelFilter] Failed to add path (rc=%d)\n", rc);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        break;

    case MSG_REMOVE_BLOCK:
        if (InputBufferLength < sizeof(SENTINEL_COMMAND)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        cmd->path[SENTINEL_MAX_PATH - 1] = L'\0';

        rc = blocklist_remove(&g_Blocklist, cmd->path);
        if (rc == BL_SUCCESS) {
            DbgPrint("[SentinelFilter] Blocked path removed: %ws\n", cmd->path);
        } else {
            DbgPrint("[SentinelFilter] Path not found for removal: %ws\n",
                     cmd->path);
            /* Not an error — path may have been removed already. */
        }
        break;

    case MSG_QUERY_STATUS:
        if (!OutputBuffer ||
            OutputBufferLength < sizeof(SENTINEL_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        {
            SENTINEL_REPLY *reply = (SENTINEL_REPLY *)OutputBuffer;
            reply->status          = 0;
            reply->blocklist_count = blocklist_count(&g_Blocklist);
            reply->blocks_total    = g_TotalBlocks;
            if (ReturnOutputBufferLength)
                *ReturnOutputBufferLength = sizeof(SENTINEL_REPLY);
        }
        break;

    default:
        DbgPrint("[SentinelFilter] Unknown message type: %u\n", cmd->type);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}
