/*
 * SentinelFilter.c — Minifilter driver for file-level enforcement.
 *
 * Phase 4, phases.md:
 *   "Minifilter driver (C, WDK) for pre-execution file blocking"
 *   DoD: "a test file is blocked from executing at all, not just
 *         suspended after starting"
 *
 * Architecture:
 *   - Registers an IRP_MJ_CREATE pre-callback (SfPreCreate)
 *   - Maintains a blocklist of normalized file paths (blocklist.c)
 *   - If a file open targets a blocked path with FILE_EXECUTE access,
 *     the callback returns STATUS_ACCESS_DENIED / FLT_PREOP_COMPLETE
 *   - User-mode Sentinel service communicates via a filter communication
 *     port to add/remove paths from the blocklist
 *
 * Safety:
 *   - SfPreCreate does ZERO disk I/O (path comparison only)
 *   - Spinlock-protected blocklist (safe at IRQL <= DISPATCH_LEVEL)
 *   - Minimal code surface in the kernel — all intelligence is user-mode
 *   - Always tested in a VM with snapshot-before-load
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "SentinelFilter.h"
#include "blocklist.h"

/* ----------------------------------------------------------------------- */
/* Forward declarations                                                    */
/* ----------------------------------------------------------------------- */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS SfUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS SfInstanceSetup(
    PCFLT_RELATED_OBJECTS    FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE              VolumeDeviceType,
    FLT_FILESYSTEM_TYPE      VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS SfPreCreate(
    PFLT_CALLBACK_DATA       Data,
    PCFLT_RELATED_OBJECTS    FltObjects,
    PVOID                   *CompletionContext);

/* Communication port callbacks (defined in communication.c). */
NTSTATUS SfPortConnect(
    PFLT_PORT ClientPort,
    PVOID     ServerPortCookie,
    PVOID     ConnectionContext,
    ULONG     SizeOfContext,
    PVOID    *ConnectionCookie);

void SfPortDisconnect(PVOID ConnectionCookie);

NTSTATUS SfPortMessage(
    PVOID  PortCookie,
    PVOID  InputBuffer,
    ULONG  InputBufferLength,
    PVOID  OutputBuffer,
    ULONG  OutputBufferLength,
    PULONG ReturnOutputBufferLength);

/* ----------------------------------------------------------------------- */
/* Globals                                                                 */
/* ----------------------------------------------------------------------- */

typedef struct _SENTINEL_SPINLOCK {
    KSPIN_LOCK  Lock;
    KIRQL       OldIrql;
} SENTINEL_SPINLOCK;

PFLT_FILTER        g_FilterHandle       = NULL;
PFLT_PORT          g_ServerPort         = NULL;
PFLT_PORT          g_ClientPort         = NULL;  /* One client at a time. */
BLOCKLIST          g_Blocklist;
SENTINEL_SPINLOCK  g_BlocklistLockCtx;
ULONG              g_TotalBlocks        = 0;     /* Stat counter. */

/* ----------------------------------------------------------------------- */
/* Kernel alloc/free/lock/unlock for blocklist                             */
/* ----------------------------------------------------------------------- */

static void* kernel_alloc(void *ctx, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, SENTINEL_POOL_TAG);
}

static void kernel_free(void *ctx, void *ptr)
{
    UNREFERENCED_PARAMETER(ctx);
    if (ptr) ExFreePoolWithTag(ptr, SENTINEL_POOL_TAG);
}

static void kernel_lock(void *ctx)
{
    SENTINEL_SPINLOCK *lockCtx = (SENTINEL_SPINLOCK *)ctx;
    KeAcquireSpinLock(&lockCtx->Lock, &lockCtx->OldIrql);
}

static void kernel_unlock(void *ctx)
{
    SENTINEL_SPINLOCK *lockCtx = (SENTINEL_SPINLOCK *)ctx;
    KeReleaseSpinLock(&lockCtx->Lock, lockCtx->OldIrql);
}

/* ----------------------------------------------------------------------- */
/* Filter registration                                                     */
/* ----------------------------------------------------------------------- */

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,                              /* Flags. */
        SfPreCreate,                    /* Pre-callback. */
        NULL                            /* No post-callback needed. */
    },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                                  /* Flags. */
    NULL,                               /* Context registration. */
    g_Callbacks,
    SfUnload,
    SfInstanceSetup,
    NULL,                               /* InstanceQueryTeardown. */
    NULL,                               /* InstanceTeardownStart. */
    NULL,                               /* InstanceTeardownComplete. */
    NULL, NULL, NULL                    /* Unused. */
};

/* ----------------------------------------------------------------------- */
/* DriverEntry                                                             */
/* ----------------------------------------------------------------------- */

NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS                   status;
    PSECURITY_DESCRIPTOR       sd    = NULL;
    OBJECT_ATTRIBUTES          oa;
    UNICODE_STRING             portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize spinlock context and blocklist.
     * The spinlock and its saved IRQL are encapsulated in g_BlocklistLockCtx
     * to avoid naked static locals and ensure clear lock context ownership. */
    KeInitializeSpinLock(&g_BlocklistLockCtx.Lock);
    g_BlocklistLockCtx.OldIrql = PASSIVE_LEVEL;

    {
        int rc = blocklist_init(
            &g_Blocklist,
            kernel_alloc, kernel_free, NULL,
            kernel_lock, kernel_unlock, &g_BlocklistLockCtx);
        if (rc != BL_SUCCESS) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    /* Register minifilter. */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration,
                               &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Create communication port.
     * Security: only SYSTEM and Administrators can connect. */
    status = FltBuildDefaultSecurityDescriptor(&sd,
                                               FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    RtlInitUnicodeString(&portName, SENTINEL_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, sd);

    status = FltCreateCommunicationPort(
        g_FilterHandle,
        &g_ServerPort,
        &oa,
        NULL,               /* ServerPortCookie. */
        SfPortConnect,
        SfPortDisconnect,
        SfPortMessage,
        1);                 /* MaxConnections = 1 (Sentinel service only). */

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    /* Start filtering. */
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(g_ServerPort);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------- */
/* Unload                                                                  */
/* ----------------------------------------------------------------------- */

NTSTATUS SfUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }
    if (g_ClientPort) {
        FltCloseClientPort(g_FilterHandle, &g_ClientPort);
        g_ClientPort = NULL;
    }
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    blocklist_destroy(&g_Blocklist);

    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------- */
/* Instance setup                                                          */
/* ----------------------------------------------------------------------- */

NTSTATUS SfInstanceSetup(
    PCFLT_RELATED_OBJECTS    FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE              VolumeDeviceType,
    FLT_FILESYSTEM_TYPE      VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    /* Only attach to fixed disk volumes with NTFS.
     * Skip network, CD-ROM, and non-NTFS volumes to minimize surface. */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM)
        return STATUS_FLT_DO_NOT_ATTACH;

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS)
        return STATUS_FLT_DO_NOT_ATTACH;

    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------- */
/* Pre-Create callback — THE HOT PATH                                      */
/*                                                                         */
/* Called for EVERY file open on attached volumes.                          */
/* MUST be fast.  Zero disk I/O.  Spinlock-protected string lookup only.   */
/* ----------------------------------------------------------------------- */

FLT_PREOP_CALLBACK_STATUS SfPreCreate(
    PFLT_CALLBACK_DATA    Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID                *CompletionContext)
{
    NTSTATUS                status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ACCESS_MASK             desiredAccess;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Fast exit: if blocklist is empty, skip everything. */
    if (g_Blocklist.count == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Skip kernel-mode callers (paging I/O, system threads).
     * We only want to block user-mode file opens. */
    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Check if the open includes execute access.
     * If no execute intent, let it through immediately. */
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (!(desiredAccess & (FILE_EXECUTE | FILE_GENERIC_EXECUTE)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Skip requests with FILE_COMPLETE_IF_OPLOCKED to avoid
     * interfering with oplock breaks (stability requirement). */
    if (Data->Iopb->Parameters.Create.Options & FILE_COMPLETE_IF_OPLOCKED)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Get the normalized file name.
     * FltGetFileNameInformation is the standard, supported way to get
     * paths in minifilter callbacks. It does NOT read the file contents. */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Check the blocklist.
     * nameInfo->Name.Buffer is the full normalized path (e.g.,
     * \Device\HarddiskVolume4\Windows\System32\evil.exe).
     * blocklist_contains handles normalization internally. */
    if (blocklist_contains(&g_Blocklist, nameInfo->Name.Buffer)) {
        /* BLOCKED — deny access. */
        Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        InterlockedIncrement((LONG *)&g_TotalBlocks);

        /* Notify user-mode (best-effort, non-blocking).
         * If no client is connected, skip silently. */
        if (g_ClientPort) {
            SENTINEL_BLOCK_EVENT evt = {0};
            ULONG replyLen = 0;

            evt.type = MSG_BLOCK_EVENT;
            evt.pid  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            evt.tid  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
            KeQuerySystemTime(&evt.timestamp);

            /* Copy path (truncate if needed). */
            {
                ULONG copyLen = nameInfo->Name.Length;
                if (copyLen > (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR))
                    copyLen = (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR);
                RtlCopyMemory(evt.path, nameInfo->Name.Buffer, copyLen);
                evt.path[copyLen / sizeof(WCHAR)] = L'\0';
            }

            /* FltSendMessage is synchronous — use a short timeout
             * to avoid blocking the file I/O path. */
            {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -10000LL * 100; /* 100ms */
                FltSendMessage(g_FilterHandle, &g_ClientPort,
                               &evt, sizeof(evt),
                               NULL, &replyLen,
                               &timeout);
                /* Ignore errors — user-mode might be slow or gone. */
            }
        }

        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
