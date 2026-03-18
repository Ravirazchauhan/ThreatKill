"""
ThreatKill - Core Scanner Engine
Detects: Rootkits, Trojans/RATs, Spyware/Keyloggers, Suspicious Startup Entries
Supports: Windows & Linux
By - RAVI CHAUHAN | github.com/Ravirazchauhan
"""

import os
import sys
import platform
import subprocess
import hashlib
import json
import re
import threading
from datetime import datetime

# Online threat intelligence (used if internet is available)
try:
    from .threat_intel import is_online, run_online_scan, get_threat_intel_summary
    HAS_INTEL = True
except ImportError:
    try:
        from threat_intel import is_online, run_online_scan, get_threat_intel_summary
        HAS_INTEL = True
    except ImportError:
        HAS_INTEL = False
from dataclasses import dataclass, field
from typing import List, Optional, Callable

OS = platform.system()  # 'Windows' or 'Linux'

# ── Known malicious hashes (MD5) - expandable database ──────────────────────
KNOWN_MALWARE_HASHES = {
    # Example known bad hashes (real tools use much larger DBs)
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty File (Suspicious)",
}

# ── Suspicious process names ─────────────────────────────────────────────────
SUSPICIOUS_PROCESSES = [
    "njrat", "darkcomet", "nanocore", "asyncrat", "quasarrat",
    "remcos", "blackshades", "poisonivy", "gh0st", "cybergate",
    "spynet", "bifrost", "xtreme", "jrat", "adwind",
    "keylogger", "revealer", "ardamax", "refog", "spyrix",
    "netbus", "subseven", "back orifice", "havoc", "cobalt",
    "meterpreter", "mimikatz", "procdump", "pwdump",
]

# ── Suspicious registry/startup paths (Windows) ──────────────────────────────
WIN_STARTUP_KEYS = [
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

# ── Suspicious Linux startup paths ───────────────────────────────────────────
LINUX_STARTUP_PATHS = [
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/cron.d/",
    "/var/spool/cron/",
    os.path.expanduser("~/.config/autostart/"),
    "/etc/systemd/system/",
]

# ── Suspicious file extensions ────────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".jar",
    ".sh", ".py", ".pl", ".rb", ".elf"
]

# ── Suspicious directories to scan ───────────────────────────────────────────
SUSPICIOUS_DIRS_WIN = [
    os.path.expanduser("~\\AppData\\Roaming"),
    os.path.expanduser("~\\AppData\\Local\\Temp"),
    "C:\\Windows\\Temp",
    "C:\\ProgramData",
]
SUSPICIOUS_DIRS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm",
    os.path.expanduser("~/.local/share"),
    os.path.expanduser("~/.cache"),
]


@dataclass
class Threat:
    threat_type: str        # rootkit | trojan | spyware | startup | suspicious_file
    name: str
    severity: str           # critical | high | medium | low
    location: str
    description: str
    action_taken: str = "detected"
    removable: bool = True
    removed: bool = False


@dataclass
class ScanResult:
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: Optional[datetime] = None
    threats: List[Threat] = field(default_factory=list)
    scanned_processes: int = 0
    scanned_files: int = 0
    scanned_startup: int = 0
    os_name: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    error: Optional[str] = None

    @property
    def duration(self):
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0

    @property
    def critical_count(self):
        return sum(1 for t in self.threats if t.severity == "critical")

    @property
    def high_count(self):
        return sum(1 for t in self.threats if t.severity == "high")

    @property
    def medium_count(self):
        return sum(1 for t in self.threats if t.severity == "medium")

    @property
    def is_clean(self):
        return len(self.threats) == 0


def md5_file(path: str) -> Optional[str]:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def get_running_processes() -> List[dict]:
    """Get all running processes cross-platform."""
    processes = []
    try:
        if OS == "Windows":
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    processes.append({"name": parts[0].lower(), "pid": parts[1]})
        else:
            out = subprocess.check_output(
                ["ps", "aux"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) > 10:
                    processes.append({"name": parts[10].lower(), "pid": parts[1]})
    except Exception:
        pass
    return processes


def scan_processes(result: ScanResult, log: Callable):
    """Scan running processes for known malware names."""
    log("🔍 Scanning running processes...")
    processes = get_running_processes()
    result.scanned_processes = len(processes)

    for proc in processes:
        name = proc["name"]
        for bad in SUSPICIOUS_PROCESSES:
            if bad in name:
                result.threats.append(Threat(
                    threat_type="trojan" if any(r in name for r in ["rat","comet","nano","async","quasar","remcos"]) else "spyware",
                    name=f"Suspicious Process: {name}",
                    severity="critical",
                    location=f"PID {proc['pid']} — {name}",
                    description=f"Process name matches known malware signature: '{bad}'. Possible RAT or spyware.",
                    removable=True,
                ))
                log(f"  ⚠️  THREAT: {name} (PID {proc['pid']})")
                break

    log(f"  ✅ Scanned {result.scanned_processes} processes")


def scan_startup_entries(result: ScanResult, log: Callable):
    """Scan startup entries for suspicious programs."""
    log("🔍 Scanning startup entries...")
    count = 0

    if OS == "Windows":
        for key in WIN_STARTUP_KEYS:
            try:
                out = subprocess.check_output(
                    ["reg", "query", key], text=True, stderr=subprocess.DEVNULL
                )
                for line in out.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("HKEY"):
                        continue
                    count += 1
                    line_lower = line.lower()
                    # Flag entries pointing to temp dirs or with suspicious names
                    suspicious = any(s in line_lower for s in [
                        "temp", "appdata\\roaming", "%tmp%", "powershell -e",
                        "cmd /c", "wscript", "cscript", "regsvr32",
                    ] + SUSPICIOUS_PROCESSES)
                    if suspicious:
                        result.threats.append(Threat(
                            threat_type="startup",
                            name=f"Suspicious Startup Entry",
                            severity="high",
                            location=f"{key}",
                            description=f"Startup entry looks suspicious: {line[:120]}",
                            removable=True,
                        ))
                        log(f"  ⚠️  STARTUP THREAT: {line[:80]}")
            except Exception:
                pass

    else:  # Linux
        for path in LINUX_STARTUP_PATHS:
            if not os.path.exists(path):
                continue
            try:
                if os.path.isfile(path):
                    count += 1
                    with open(path, "r", errors="ignore") as f:
                        content = f.read().lower()
                    for bad in SUSPICIOUS_PROCESSES:
                        if bad in content:
                            result.threats.append(Threat(
                                threat_type="startup",
                                name="Suspicious Startup Script",
                                severity="high",
                                location=path,
                                description=f"Startup file contains suspicious keyword: '{bad}'",
                                removable=False,
                            ))
                            log(f"  ⚠️  STARTUP THREAT in {path}")
                else:
                    for fname in os.listdir(path):
                        count += 1
                        fpath = os.path.join(path, fname)
                        try:
                            with open(fpath, "r", errors="ignore") as f:
                                content = f.read().lower()
                            for bad in SUSPICIOUS_PROCESSES:
                                if bad in content:
                                    result.threats.append(Threat(
                                        threat_type="startup",
                                        name=f"Suspicious Startup: {fname}",
                                        severity="high",
                                        location=fpath,
                                        description=f"Contains suspicious keyword: '{bad}'",
                                        removable=False,
                                    ))
                                    log(f"  ⚠️  STARTUP THREAT: {fpath}")
                                    break
                        except Exception:
                            pass
            except Exception:
                pass

    result.scanned_startup = count
    log(f"  ✅ Scanned {count} startup entries")


def scan_suspicious_files(result: ScanResult, log: Callable, quick=True):
    """Scan suspicious directories for malware by hash and name."""
    log("🔍 Scanning suspicious directories...")
    dirs = SUSPICIOUS_DIRS_WIN if OS == "Windows" else SUSPICIOUS_DIRS_LINUX
    count = 0
    max_files = 300 if quick else 5000

    for d in dirs:
        if not os.path.exists(d):
            continue
        try:
            for root, _, files in os.walk(d):
                for fname in files:
                    if count >= max_files:
                        break
                    fpath = os.path.join(root, fname)
                    count += 1

                    # Hash check
                    fhash = md5_file(fpath)
                    if fhash and fhash in KNOWN_MALWARE_HASHES:
                        result.threats.append(Threat(
                            threat_type="trojan",
                            name=f"Known Malware: {KNOWN_MALWARE_HASHES[fhash]}",
                            severity="critical",
                            location=fpath,
                            description=f"File matches known malware hash ({fhash}): {KNOWN_MALWARE_HASHES[fhash]}",
                            removable=True,
                        ))
                        log(f"  🔴 MALWARE HASH MATCH: {fpath}")
                        continue

                    # Name-based check
                    fname_lower = fname.lower()
                    for bad in SUSPICIOUS_PROCESSES:
                        if bad in fname_lower:
                            result.threats.append(Threat(
                                threat_type="trojan",
                                name=f"Suspicious File: {fname}",
                                severity="high",
                                location=fpath,
                                description=f"Filename matches known malware pattern: '{bad}'",
                                removable=True,
                            ))
                            log(f"  ⚠️  SUSPICIOUS FILE: {fpath}")
                            break
        except PermissionError:
            pass

    result.scanned_files = count
    log(f"  ✅ Scanned {count} files")


def scan_rootkit_indicators(result: ScanResult, log: Callable):
    """Check for rootkit indicators (hidden processes, suspicious kernel modules)."""
    log("🔍 Scanning for rootkit indicators...")

    if OS == "Linux":
        # Check for hidden processes (ps vs /proc discrepancy)
        try:
            ps_pids = set()
            out = subprocess.check_output(["ps", "-e", "-o", "pid="], text=True, stderr=subprocess.DEVNULL)
            for line in out.strip().splitlines():
                ps_pids.add(line.strip())

            proc_pids = set()
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(entry)

            hidden = proc_pids - ps_pids
            if len(hidden) > 5:  # small discrepancy is normal
                result.threats.append(Threat(
                    threat_type="rootkit",
                    name="Hidden Processes Detected",
                    severity="critical",
                    location="/proc vs ps output",
                    description=f"{len(hidden)} processes visible in /proc but not in ps output — strong rootkit indicator.",
                    removable=False,
                ))
                log(f"  🔴 ROOTKIT INDICATOR: {len(hidden)} hidden processes")
        except Exception:
            pass

        # Check for suspicious kernel modules
        try:
            out = subprocess.check_output(["lsmod"], text=True, stderr=subprocess.DEVNULL)
            suspicious_mods = ["rootkit", "rkmod", "diamorphine", "reptile", "suterusu", "adore", "knark", "override_usermodehelper"]
            for line in out.splitlines():
                mod_name = line.split()[0].lower() if line.split() else ""
                for bad in suspicious_mods:
                    if bad in mod_name:
                        result.threats.append(Threat(
                            threat_type="rootkit",
                            name=f"Suspicious Kernel Module: {mod_name}",
                            severity="critical",
                            location=f"lsmod: {mod_name}",
                            description=f"Kernel module '{mod_name}' matches known rootkit pattern.",
                            removable=False,
                        ))
                        log(f"  🔴 ROOTKIT MODULE: {mod_name}")
        except Exception:
            pass

    elif OS == "Windows":
        # Check for suspicious drivers
        try:
            out = subprocess.check_output(
                ["driverquery", "/FO", "CSV", "/NH"], text=True, stderr=subprocess.DEVNULL
            )
            # Use specific terms - avoid false positives like HID (Human Interface Device)
            suspicious_drivers = ["rootkit", "rkdrv", "hookdrv", "stealth", "injector", "diamorphine", "reptile"]
            for line in out.splitlines():
                line_lower = line.lower()
                for bad in suspicious_drivers:
                    if bad in line_lower:
                        result.threats.append(Threat(
                            threat_type="rootkit",
                            name=f"Suspicious Driver Detected",
                            severity="critical",
                            location=line[:100],
                            description=f"Driver name contains suspicious keyword: '{bad}'",
                            removable=False,
                        ))
                        log(f"  🔴 ROOTKIT DRIVER: {line[:60]}")
        except Exception:
            pass

    log("  ✅ Rootkit scan complete")


def remove_threat(threat: Threat, log: Callable) -> bool:
    """Attempt to remove a detected threat."""
    try:
        if threat.threat_type in ("trojan", "suspicious_file") and os.path.isfile(threat.location):
            os.remove(threat.location)
            threat.removed = True
            threat.action_taken = "removed"
            log(f"  🗑️  Removed: {threat.location}")
            return True
        elif threat.threat_type == "startup" and OS == "Windows":
            # Remove registry key
            parts = threat.location.split("\\")
            if len(parts) > 1:
                subprocess.run(["reg", "delete", threat.location, "/f"],
                               capture_output=True)
                threat.removed = True
                threat.action_taken = "removed from startup"
                log(f"  🗑️  Removed startup entry: {threat.location}")
                return True
    except Exception as e:
        log(f"  ❌ Could not remove {threat.location}: {e}")
    return False


class ThreatScanner:
    def __init__(self):
        self._stop = False

    def stop(self):
        self._stop = True

    def run_full_scan(self, log_callback: Callable, done_callback: Callable, quick=True):
        """Run full scan in a background thread."""
        def _scan():
            result = ScanResult()
            try:
                log_callback(f"🛡️  ThreatKill scan started — {result.os_name}")
                log_callback(f"{'─'*50}")

                if not self._stop:
                    scan_processes(result, log_callback)
                if not self._stop:
                    scan_startup_entries(result, log_callback)
                if not self._stop:
                    scan_suspicious_files(result, log_callback, quick=quick)
                if not self._stop:
                    scan_rootkit_indicators(result, log_callback)

                # ── Online threat intelligence ──────────────────────────
                if not self._stop and HAS_INTEL:
                    summary = get_threat_intel_summary(log_callback)
                    if summary["online"]:
                        log_callback("🌐 Running online threat intelligence checks...")
                        # Collect all scanned files for online verification
                        dirs = SUSPICIOUS_DIRS_WIN if OS == "Windows" else SUSPICIOUS_DIRS_LINUX
                        files_to_check = []
                        for d in dirs:
                            if not os.path.exists(d):
                                continue
                            try:
                                for root, _, files in os.walk(d):
                                    for fname in files[:30]:  # limit to 30 per dir
                                        fpath = os.path.join(root, fname)
                                        if os.path.getsize(fpath) < 50 * 1024 * 1024:  # skip >50MB
                                            files_to_check.append(fpath)
                            except Exception:
                                pass
                        online_threats = run_online_scan(files_to_check[:100], log_callback)
                        for ot in online_threats:
                            # Convert dict to Threat object
                            result.threats.append(Threat(
                                threat_type="trojan",
                                name=ot["title"],
                                severity=ot["severity"],
                                location=ot["location"],
                                description=ot["description"],
                                action_taken="detected (online)",
                                removable=ot.get("removable", True),
                            ))
                        log_callback(f"  ✅ Online check complete — {len(online_threats)} online hit(s)")
                    else:
                        log_callback("  ⚠️  No internet — skipping online threat intelligence")

                result.scan_end = datetime.now()
                log_callback(f"{'─'*50}")
                log_callback(f"✅ Scan complete in {result.duration:.1f}s — {len(result.threats)} threat(s) found")
            except Exception as e:
                result.error = str(e)
                log_callback(f"❌ Scan error: {e}")

            done_callback(result)

        t = threading.Thread(target=_scan, daemon=True)
        t.start()
