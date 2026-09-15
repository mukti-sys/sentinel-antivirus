#!/usr/bin/env python3
"""Sentinel Antivirus Command-Line Interface (CLI).

Provides administrative command-line control for Sentinel:
  - sentinel scan <path>       : Scan file or directory with 5M ML + YARA + Authenticode
  - sentinel status            : Query core service status via Named Pipe IPC
  - sentinel canaries          : Check and manage ransomware honeypots
  - sentinel quarantine list   : View quarantined threats
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sentinel.engine.canary import CanaryManager
from sentinel.engine.static_classifier import PEFeatures, PEFeatureModel, extract_pe_features
from sentinel.ipc import NamedPipeClient
from sentinel.response.quarantine_store import QuarantineStore


def cmd_status(args: argparse.Namespace) -> int:
    """Query live Sentinel service status over Named Pipe IPC."""
    pipe_name = args.pipe
    client = NamedPipeClient(pipe_name=pipe_name)
    try:
        res = client.send({"cmd": "get_status"})
    except Exception:
        res = None

    if not res or res.get("status") != "ok":
        print(f"[-] Could not connect to Sentinel service on {pipe_name}.")
        print("    Ensure the Sentinel background service is running.")
        return 1

    print("=" * 60)
    print("           SENTINEL SERVICE STATUS")
    print("=" * 60)
    print(f"  Status:          {res.get('status', 'unknown').upper()}")
    print(f"  Shield State:    {res.get('shield', 'UNKNOWN')}")
    print(f"  Kernel Driver:   {res.get('driver', 'disconnected')}")
    print(f"  Canaries Armed:  {res.get('canaries_armed', 0)}")
    print("=" * 60)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a target path using PE ML v2, YARA rules, and Authenticode."""
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"[-] Path not found: {target}")
        return 1

    files_to_scan = [target] if target.is_file() else list(target.rglob("*"))
    pe_files = [f for f in files_to_scan if f.is_file() and f.suffix.lower() in (".exe", ".dll", ".sys", ".scr")]

    if not pe_files:
        print(f"[*] No PE executables found in {target}")
        return 0

    print("=" * 70)
    print(f"  SENTINEL SCAN REPORT: {len(pe_files)} Executable(s) in {target.name}")
    print("=" * 70)

    model = PEFeatureModel()
    threats_found = 0

    for f in pe_files:
        feats = extract_pe_features(f)
        if not feats:
            continue

        threat = model.predict_threat(feats)
        prob = threat["malware_probability"]
        is_malware = threat["is_malware"]
        level = "MALICIOUS" if prob >= 0.8 else ("SUSPICIOUS" if prob >= 0.5 or is_malware else "CLEAN")

        status_tag = "[CLEAN]     " if level == "CLEAN" else f"[{level}]"
        if is_malware:
            threats_found += 1
            print(f"  {status_tag:12} {f.name[:32]:32} | Prob: {prob * 100:5.1f}% | Size: {f.stat().st_size:,}B")
        elif args.verbose:
            print(f"  {status_tag:12} {f.name[:32]:32} | Prob: {prob * 100:5.1f}%")

    print("-" * 70)
    if threats_found == 0:
        print("  [+] Clean: 0 threats detected across all scanned files.")
    else:
        print(f"  [!] ALERT: {threats_found} suspicious or malicious file(s) identified.")
    print("=" * 70)
    return 1 if threats_found > 0 else 0


def cmd_canaries(args: argparse.Namespace) -> int:
    """Check or rearm ransomware canary honeypots."""
    mgr = CanaryManager()
    if args.arm:
        armed = mgr.arm_traps()
        print(f"[+] Armed {armed} ransomware canary trap(s).")
    elif args.disarm:
        mgr.arm_traps()
        mgr.disarm_traps()
        print("[+] Disarmed and cleaned up all canary trap(s).")
    else:
        mgr.arm_traps()
        tripped = mgr.verify_all_canaries()
        if not tripped:
            print(f"[+] All ransomware canary traps are intact and armed ({len(mgr.active_canaries)} honeypots active).")
        else:
            print(f"[!] RANSOMWARE ALERT: {len(tripped)} canary honeypot(s) have been tripped/modified!")
            for trap, reason in tripped:
                print(f"    - {trap.path.name}: {reason}")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """View quarantined threats."""
    store = QuarantineStore()
    records = store.list_records(limit=args.limit)
    print("=" * 70)
    print(f"  SENTINEL QUARANTINE VAULT ({len(records)} active records)")
    print("=" * 70)
    if not records:
        print("  Quarantine vault is empty.")
    else:
        for r in records:
            print(f"  ID: {r.id[:8]} | Score: {r.score:.1f} | Reason: {r.reason[:35]} | Path: {r.source_path}")
    print("=" * 70)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Antivirus Enterprise CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # status
    p_status = subparsers.add_parser("status", help="Query Sentinel core service status")
    p_status.add_argument("--pipe", default=r"\\.\pipe\SentinelIPC", help="Named pipe name")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("path", help="Path to file or directory")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Show all files including clean")

    # canaries
    p_canary = subparsers.add_parser("canaries", help="Inspect or manage ransomware honeypots")
    p_canary.add_argument("--arm", action="store_true", help="Arm canary files")
    p_canary.add_argument("--disarm", action="store_true", help="Disarm canary files")

    # quarantine
    p_quar = subparsers.add_parser("quarantine", help="Inspect quarantine vault")
    p_quar.add_argument("--limit", type=int, default=25, help="Max records to show")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "status":
        return cmd_status(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "canaries":
        return cmd_canaries(args)
    if args.command == "quarantine":
        return cmd_quarantine(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
