#!/usr/bin/env python3
"""
Aegis Audit Log Viewer
Queries and renders forensic event records from aegis_audit.db using Rich.
"""

import sqlite3
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime

console = Console()
DB_PATH = Path(__file__).resolve().parent / "aegis_audit.db"
if os.getenv("AEGIS_DATA_DIR"):
    DB_PATH = Path(os.environ["AEGIS_DATA_DIR"]) / "aegis_audit.db"

def display_audit_logs(limit: int = 25, only_anomalies: bool = False):
    if not DB_PATH.exists():
        console.print("[bold red][!] No audit database found at aegis_audit.db[/bold red]")
        return

    query = """
        SELECT id, timestamp, os_type, pid, parent_pid, process_name, 
               cmdline, is_elevated, anomaly_score, is_anomaly, mitigation_status
        FROM security_events
    """
    if only_anomalies:
        query += " WHERE is_anomaly = 1"
    query += " ORDER BY id DESC LIMIT ?;"

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(query, (limit,)).fetchall()

    if not rows:
        console.print("[yellow][*] No matching records found in audit database.[/yellow]")
        return

    table = Table(
        title=f"Aegis Forensic Audit Log (Last {len(rows)} Events)",
        header_style="bold cyan",
        border_style="dim",
        show_lines=True
    )

    table.add_column("ID", justify="right", style="dim", width=5)
    table.add_column("Time", justify="center", width=10)
    table.add_column("OS", justify="center", width=8)
    table.add_column("PID / PPID", justify="center", width=12)
    table.add_column("Process Name", style="bold", width=18)
    table.add_column("Anomaly", justify="center", width=10)
    table.add_column("Mitigation Status", width=26)
    table.add_column("Command Preview", style="dim", overflow="ellipsis")

    for row in rows:
        (
            event_id, ts, os_type, pid, ppid, proc_name,
            cmdline, is_elevated, score, is_anomaly, status
        ) = row

        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        elevated_badge = "[red]▲[/red] " if is_elevated else ""
        proc_display = f"{elevated_badge}{proc_name}"
        
        # Colorize anomaly scores
        if is_anomaly or score >= 0.70:
            score_display = f"[bold red]{score:.1%}[/bold red]"
        elif score >= 0.40:
            score_display = f"[yellow]{score:.1%}[/yellow]"
        else:
            score_display = f"[green]{score:.1%}[/green]"

        # Colorize status
        if "SUSPENDED" in status:
            status_display = f"[bold red]{status}[/bold red]"
        elif "SKIPPED" in status:
            status_display = f"[cyan]{status}[/cyan]"
        else:
            status_display = f"[dim green]{status}[/dim green]"

        cmd_preview = (cmdline[:45] + "...") if len(cmdline) > 45 else (cmdline or "N/A")

        table.add_row(
            str(event_id),
            time_str,
            os_type.upper(),
            f"{pid} / {ppid}",
            proc_display,
            score_display,
            status_display,
            cmd_preview
        )

    console.print(table)

if __name__ == "__main__":
    import sys
    only_anom = "--anomalies" in sys.argv or "-a" in sys.argv
    display_audit_logs(only_anomalies=only_anom)