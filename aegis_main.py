#!/usr/bin/env python3
"""
Aegis Hardened Runtime Security Engine
Main entry point: Runs in Report-Only by default, supports --enforce.
"""

import argparse
import base64
import platform
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from core.schema import SystemEvent
from core.ai_brain import AIEvaluator
from core.db import AuditDatabase
from core.security import SecurityError
from mitigations.enforcer import enforce_safeguards_and_suspend

console = Console()

def trigger_interactive_alert(process_name: str, pid: int, score: float):
    process_name_b64 = base64.b64encode(process_name.encode("utf-8")).decode("ascii")
    ps_cmd = f"""
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null

    $processName = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{process_name_b64}'))
    $template = @"
    <toast duration=""long"">
        <visual>
            <binding template=""ToastGeneric"">
                <text>AEGIS ALERT: Threat Detected ({score:.1f}%)</text>
                <text>Process: $processName (PID: {pid})</text>
                <text>Suspicious process activity detected. Choose an action.</text>
            </binding>
        </visual>
        <actions>
            <action content=""Terminate Process"" arguments=""terminate_{pid}"" activationType=""foreground""/>
            <action content=""Ignore / Allow"" arguments=""ignore_{pid}"" activationType=""background""/>
        </actions>
    </toast>
"@

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)

    Register-ObjectEvent -InputObject $toast -EventName Activated -Action {{
        param($sender, $args)
        $argument = $args.Arguments
        if ($argument -like ""terminate_*"") {{
            $targetPid = [int]$argument.Split('_')[1]
            Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
        }}
    }} | Out-Null

    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(""Aegis Runtime Defense"")
    $notifier.Show($toast)
    Start-Sleep -Seconds 15
    """

    def notify():
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
                creationflags=0x08000000,
                timeout=20,
                check=False
            )
        except (OSError, subprocess.SubprocessError):
            pass

    threading.Thread(target=notify, daemon=True).start()

def run_preflight_tests() -> bool:
    console.print("[bold cyan][*] Running pre-flight security test suite...[/bold cyan]")
    loader = unittest.TestLoader()
    tests_dir = Path(__file__).resolve().parent / "tests"
    suite = loader.discover(str(tests_dir), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        console.print("[bold green][✓] Pre-flight verification PASSED (All tests green).[/bold green]\n")
        return True
    else:
        console.print(f"[bold red][✗] Pre-flight verification FAILED ({len(result.errors)} errors, {len(result.failures)} failures).[/bold red]\n")
        return False

def on_collector_status(status_level: str, message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status_level in ("CRITICAL_FAILURE", "ERROR"):
        console.print(f"[bold red][{timestamp}] [COLLECTOR {status_level}][/bold red] {message}")
    elif status_level == "DEGRADED":
        console.print(f"[yellow][{timestamp}] [COLLECTOR DEGRADED][/yellow] {message}")
    else:
        console.print(f"[dim cyan][{timestamp}] [COLLECTOR {status_level}][/dim cyan] {message}")

def make_event_handler(evaluator: AIEvaluator, db: AuditDatabase, enforcement_enabled: bool):
    def handle_event(event: SystemEvent):
        is_anomaly, score = evaluator.score_event(event)

        if is_anomaly:
            if enforcement_enabled:
                success, status = enforce_safeguards_and_suspend(
                    pid=event.pid,
                    process_name=event.process_name,
                    os_type=event.os_type
                )
            else:
                status = "REPORT_ONLY_ANOMALY_NOTED"

            db.log_event(event, score, is_anomaly=True, status=status)

            if event.os_type.lower() == "windows":
                trigger_interactive_alert(
                    process_name=event.process_name,
                    pid=event.pid,
                    score=score * 100
                )

            mode_tag = "[bold red][ENFORCING][/bold red]" if enforcement_enabled else "[bold yellow][REPORT-ONLY][/bold yellow]"
            console.print(Panel.fit(
                f"{mode_tag} [bold red]ANOMALY DETECTED (Score: {score:.2%})[/bold red]\n"
                f"[yellow]PID:[/yellow] {event.pid} | [yellow]Parent:[/yellow] {event.parent_pid} | [yellow]App:[/yellow] {event.process_name}\n"
                f"[dim]Command: {event.cmdline}[/dim]\n"
                f"[bold cyan]Action:[/bold cyan] {status}",
                border_style="red" if enforcement_enabled else "yellow"
            ))
        else:
            db.log_event(event, score, is_anomaly=False, status="MONITORED_SAFE")
            console.print(f"[dim green][SAFE][/dim green] PID: {event.pid:<6} | {event.process_name:<22} | Score: {score:.1%}")

    return handle_event

def main():
    parser = argparse.ArgumentParser(description="Aegis Runtime Security Engine")
    parser.add_argument(
        "--enforce", 
        action="store_true", 
        help="Enable active process suspension (Defaults to False/Report-Only)"
    )
    args = parser.parse_args()

    current_os = platform.system().lower()

    if current_os not in {"windows", "linux"}:
        console.print(f"[bold red]Unsupported operating system: {current_os}[/bold red]")
        sys.exit(1)

    # 2. Gate enforcement behind passing tests
    if args.enforce:
        console.print("[bold yellow][!] --enforce requested: Gating active mitigation behind automated tests...[/bold yellow]")
        if not run_preflight_tests():
            console.print("[bold red][FATAL] Refusing to start in ENFORCE mode due to failing tests. Exiting.[/bold red]")
            sys.exit(1)
        mode_str = "[bold red]ACTIVE ENFORCEMENT[/bold red]"
    else:
        mode_str = "[bold yellow]REPORT-ONLY (Audit Mode)[/bold yellow]"

    console.print("[bold cyan]====================================================[/bold cyan]")
    console.print(f"[bold cyan]  AEGIS HARDENED ENGINE | OS: {current_os.upper()}[/bold cyan]")
    console.print(f"[bold cyan]  Operating Mode: {mode_str}[/bold cyan]")
    console.print("[bold cyan]====================================================[/bold cyan]\n")

    db = None
    try:
        db = AuditDatabase()
        evaluator = AIEvaluator()
        handler = make_event_handler(evaluator, db, enforcement_enabled=args.enforce)

        if current_os == "windows":
            from collectors.windows_collector import stream_windows_events
            stream_windows_events(handler, on_collector_status)
        else:
            from collectors.linux_collector import stream_linux_events
            stream_linux_events(handler)
    except SecurityError as exc:
        console.print(f"[bold red][FATAL SECURITY ERROR] {exc}[/bold red]")
        sys.exit(1)
    finally:
        if db is not None:
            db.flush_and_close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red][*] Engine stopped cleanly.[/bold red]")