"""Sentinel Behavioral Sandbox — executes untrusted binaries in isolated
Windows Job Objects with strict CPU, memory, time, and UI limits.
"""
from __future__ import annotations

from sentinel.sandbox.job_object import SandboxJobObject
from sentinel.sandbox.runner import SandboxReport, SandboxRunner

__all__ = ["SandboxJobObject", "SandboxRunner", "SandboxReport"]
