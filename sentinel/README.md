# Sentinel

A personal **behavioral** security layer for Windows — a complement to
Windows Defender, not a replacement. Sentinel watches *behavior*
(cryptomining, ransomware-style file attacks, brute-force logins, LOLBin
abuse) and reacts the moment malicious behavior is observed, never blocking
a file just because it's new. It runs fully independent of whether
Defender's real-time protection is on or off, and is deliberately lighter
on alerts and resources than Defender's default posture.

> See the project root for the full design docs: `prd.md`, `architecture.md`,
> `phases.md`, `plan.md`.

## Status

| Phase | Focus | Status |
|-------|-------|--------|
| 0 | Environment / scaffold | ✅ Done |
| 1 | Telemetry sensors | pending |
| 2 | Detection engines | pending |
| 3 | Response + hardening | pending |
| 4 | Kernel enforcement (minifilter) | not started — needs explicit go-ahead |

See `PROGRESS.md` (project root) for the running log of what's done,
verified, and next.

## Layout

```
sentinel/
├── config/      settings.yaml + Sigma-style rules/
├── sensors/     etw / fs / network / eventlog
├── engine/      event_bus, schema, rule_engine, ml_engine, static_classifier, scoring
├── response/    responder, quarantine_store, notifier
├── intel/       virustotal_client, abusech_client
├── ui/          tray_app
├── tests/       test_harness/ (safe synthetic only) + unit/
└── data/        events.db, quarantine/
```

## Setup

```bash
python -m venv .venv
source .venv/Scripts/activate        # Windows (Git Bash)
pip install pywin32 psutil watchdog yara-python scikit-learn pywintrace requests pyyaml
```

ETW consumption and Security Event Log access (Phase 1+) require an
**elevated / Administrator** terminal.

## Run (Phase 0 check)

```bash
python -m sentinel.sensors.etw_sensor
```

## Safety note

Never test with real malware. Use only the safe synthetic harnesses in
`tests/test_harness/` (EICAR file, self-contained benign scripts, CPU
busy-loops, deliberate failed logins, dummy-file rewrites). Each harness has
a README noting exactly what it simulates and confirming it is harmless.
