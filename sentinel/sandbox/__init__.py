"""Sentinel Dynamic Analysis & Behavioral Sandbox — user-space CPU & API emulation
and isolated process containment for untrusted binaries.
"""
from __future__ import annotations

from sentinel.sandbox.emulator import DynamicEmulator, EmulationResult
from sentinel.sandbox.isolation import SandboxIsolation
from sentinel.sandbox.runner import DroppedFile, SandboxReport, SandboxRunner

try:
    from sentinel.sandbox.job_object import SandboxJobObject
except ImportError:
    SandboxJobObject = None  # type: ignore

__all__ = [
    "DynamicEmulator",
    "EmulationResult",
    "SandboxIsolation",
    "SandboxJobObject",
    "SandboxRunner",
    "SandboxReport",
    "DroppedFile",
]
