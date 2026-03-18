#!/usr/bin/env python3
"""
ThreatKill - Malware & Rootkit Removal Tool
By - RAVI CHAUHAN | github.com/Ravirazchauhan

Usage:
    python run.py           # Launch GUI
    python run.py --cli     # CLI scan only
"""
import sys
import os

# Always find gui/ and core/ folders regardless of where you run from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)


def launch_gui():
    # Check tkinter first
    try:
        import tkinter as tk
    except ImportError:
        print("ERROR: tkinter is not installed.")
        print("Fix: Reinstall Python from python.org")
        sys.exit(1)

    try:
        from gui.app import main
        main()
    except ImportError as e:
        print(f"Import Error: {e}")
        print(f"Current folder : {os.getcwd()}")
        print(f"Files found    : {os.listdir(BASE_DIR)}")
        print("Make sure core/ and gui/ folders exist inside ThreatKill/")
        sys.exit(1)


def launch_cli():
    try:
        from core.scanner import ThreatScanner
    except ImportError as e:
        print(f"Import Error: {e}")
        sys.exit(1)

    banner = (
        "\n"
        " _____ _                    _   _  ___ _ _\n"
        "|_   _| |__  _ __ ___  __ _| |_| |/ (_) | |\n"
        "  | | | '_ \\| '__/ _ \\/ _` | __| ' /| | | |\n"
        "  | | | | | | | |  __/ (_| | |_| . \\| | | |\n"
        "  |_| |_| |_|_|  \\___|\\__,_|\\__|_|\\_\\_|_|_|\n"
        "\n"
        "  By - RAVI CHAUHAN | github.com/Ravirazchauhan\n"
    )
    print(banner)

    import threading
    result_holder = []
    done_event = threading.Event()

    def done(result):
        result_holder.append(result)
        done_event.set()

    scanner = ThreatScanner()
    scanner.run_full_scan(log_callback=print, done_callback=done)
    done_event.wait()

    result = result_holder[0]
    print(f"\n{'='*50}")
    print(f"SCAN COMPLETE")
    print(f"Threats found : {len(result.threats)}")
    print(f"Critical      : {result.critical_count}")
    print(f"High          : {result.high_count}")
    print(f"Duration      : {result.duration:.1f}s")

    if result.threats:
        print("\nTHREATS:")
        for t in result.threats:
            print(f"  [{t.severity.upper():8}] {t.name} - {t.location[:60]}")


if __name__ == "__main__":
    if "--cli" in sys.argv:
        launch_cli()
    else:
        launch_gui()
