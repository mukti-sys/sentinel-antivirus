"""Sentinel kernel bridge — __init__.py

Exports KernelBridge for the rest of Sentinel to use.
Graceful degradation: if the kernel driver is not loaded,
all bridge operations are silent no-ops.
"""
from __future__ import annotations

from sentinel.kernel.bridge import KernelBridge

__all__ = ["KernelBridge"]
