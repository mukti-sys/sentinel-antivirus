# Test Harnesses — Safe Synthetic Detectors

This directory contains intentionally harmless scripts that exercise each
detection engine end-to-end against the live Sentinel system.

> **Safety:** none of these scripts contain real malware, exploits, or
> destructive behavior. Each simulates ONLY the observable pattern a detector
> looks for (CPU usage, file writes, login failures, etc.) using harmless data.

## How to use

1. Start Sentinel (or the specific engine you're testing)
2. Run the harness script for the detector you want to validate
3. Check that the detector fires and produces a scored signal in the event bus

## Harnesses

| Script | Detector Validated | What It Does |
|---|---|---|
| `eicar_harness.py` | Static classifier (VT hash) | Drops the EICAR test string to a temp file and triggers a `file_write` event |
| `cpu_busy_loop.py` | Cryptomining heuristic | Spins a CPU busy-loop for a configurable duration to trigger `cpu_sustained` |
| `file_burst.py` | Ransomware heuristic | Rapidly rewrites a batch of dummy files with random bytes in a test folder |
| `failed_login.py` | Brute-force heuristic | Generates synthetic `login_failed` events to trigger `failed_login_burst` |
| `inject_self.py` | DLL/behavioral detector | Calls `CreateRemoteThread` on its own process (self-injection, harmless) |

## Important Notes

- **Never test with real malware.** plan.md Section 7 explicitly forbids it.
- These harnesses are for **developer validation**, not production use.
- The EICAR string is the industry-standard AV test — every AV on earth
  recognizes it, and it is completely harmless (see `eicar_harness.py`).
- `inject_self.py` only targets its OWN process (self-injection). It never
  touches another process.
