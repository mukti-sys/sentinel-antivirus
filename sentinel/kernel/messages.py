"""ctypes structures matching driver/SentinelFilter/SentinelFilter.h.

These MUST be kept in sync with the C header.  Any mismatch causes
silent data corruption in kernel ↔ user-mode communication.

Layout notes:
- All structures use ULONG (4 bytes) alignment.
- WCHAR arrays are 520 elements (SENTINEL_MAX_PATH).
- LARGE_INTEGER is 8 bytes (ctypes.c_longlong).
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

# Must match SentinelFilter.h exactly.
SENTINEL_MAX_PATH = 520

# Message types: user-mode → kernel
MSG_ADD_BLOCK    = 1
MSG_REMOVE_BLOCK = 2
MSG_QUERY_STATUS = 3

# Message types: kernel → user-mode
MSG_BLOCK_EVENT  = 10

# Communication port name.
SENTINEL_PORT_NAME = r"\SentinelFilterPort"


class SENTINEL_COMMAND(ctypes.Structure):
    """User-mode → kernel command (MSG_ADD_BLOCK, MSG_REMOVE_BLOCK, etc.)."""
    _fields_ = [
        ("type", wintypes.ULONG),
        ("path", ctypes.c_wchar * SENTINEL_MAX_PATH),
    ]


class SENTINEL_REPLY(ctypes.Structure):
    """Kernel → user-mode reply to MSG_QUERY_STATUS."""
    _fields_ = [
        ("status", wintypes.ULONG),
        ("blocklist_count", wintypes.ULONG),
        ("blocks_total", wintypes.ULONG),
    ]


class LARGE_INTEGER(ctypes.Structure):
    """Windows LARGE_INTEGER (8-byte signed integer)."""
    _fields_ = [
        ("QuadPart", ctypes.c_longlong),
    ]


class SENTINEL_BLOCK_EVENT(ctypes.Structure):
    """Kernel → user-mode notification when a file access was blocked."""
    _fields_ = [
        ("type", wintypes.ULONG),
        ("path", ctypes.c_wchar * SENTINEL_MAX_PATH),
        ("pid", wintypes.ULONG),
        ("tid", wintypes.ULONG),
        ("timestamp", LARGE_INTEGER),
    ]


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    """FLT_MESSAGE_HEADER prepended by FilterGetMessage.
    This is the standard header that the filter manager adds to every
    message received via FilterGetMessage.
    """
    _fields_ = [
        ("ReplyLength", wintypes.ULONG),
        ("MessageId", ctypes.c_ulonglong),
    ]


class SENTINEL_GET_MESSAGE(ctypes.Structure):
    """Full structure received by FilterGetMessage:
    header + block event payload."""
    _fields_ = [
        ("header", FILTER_MESSAGE_HEADER),
        ("event", SENTINEL_BLOCK_EVENT),
    ]
