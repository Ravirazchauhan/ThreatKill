# ⚔ ThreatKill

> A cross-platform GUI malware & rootkit removal tool built in Python.

![Python](https://img.shields.io/badge/python-3.9+-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green?style=flat-square)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

**By — RAVI CHAUHAN** &nbsp;|&nbsp; 🔗 [github.com/Ravirazchauhan](https://github.com/Ravirazchauhan)

---

## 🛡️ What It Detects

| Type | Detection Method |
|---|---|
| ☠ **Rootkits** | Hidden process detection, suspicious kernel modules/drivers |
| 🐴 **Trojans / RATs** | Process & file name matching against 30+ known RAT signatures |
| 👁 **Spyware / Keyloggers** | Process scanning + suspicious directory file analysis |
| ⚡ **Startup Entries** | Registry scan (Windows) + init/cron/systemd analysis (Linux) |
| 🔐 **Known Malware** | MD5 hash matching against malware hash database |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/Ravirazchauhan/ThreatKill.git
cd ThreatKill

# Launch the GUI (no install needed!)
python run.py

# Or run CLI only
python run.py --cli
```

> **Windows:** Run as Administrator for full scan coverage  
> **Linux:** Run with `sudo python run.py` for kernel module scanning

---

## 📁 Project Structure

```
ThreatKill/
├── run.py                   # Main entry point (GUI + CLI)
├── requirements.txt         # No external deps needed!
├── core/
│   ├── __init__.py
│   └── scanner.py           # Detection engine
├── gui/
│   ├── __init__.py
│   └── app.py               # Tkinter GUI application
└── utils/
    └── __init__.py
```

---

## 🖥️ GUI Features

- **Dark security-themed interface**
- **Live scan log** with colour-coded output
- **Threat list** with severity badges (Critical / High / Medium / Low)
- **One-click removal** for removable threats
- **Remove All** button to clean everything at once
- **Stats dashboard** — threats, processes scanned, files scanned
- **About tab** with full capability list

---

## ⚙️ How It Works

### Process Scanner
Checks all running processes against 30+ known malware name signatures including NjRAT, DarkComet, NanoCore, AsyncRAT, Mimikatz, and more.

### Startup Scanner
- **Windows:** Scans 4 Run/RunOnce registry keys for suspicious entries
- **Linux:** Scans `/etc/init.d/`, `/etc/cron.d/`, `~/.config/autostart/`, systemd units

### File Scanner
Scans high-risk directories (Temp, AppData, /tmp, /dev/shm) for files matching malware signatures or known bad MD5 hashes.

### Rootkit Detector
- **Linux:** Compares `/proc` PID list vs `ps` output — discrepancies indicate hidden processes. Also scans `lsmod` for suspicious kernel modules.
- **Windows:** Scans loaded drivers for suspicious names.

---

## ⚠️ Legal Notice

> This tool is intended **for authorised use only**.  
> Only scan systems you own or have explicit permission to scan.  
> Run as **Administrator** (Windows) or **root** (Linux) for full effectiveness.

---

## 👤 Author

**RAVI CHAUHAN**  
🔗 GitHub: [https://github.com/Ravirazchauhan](https://github.com/Ravirazchauhan)
