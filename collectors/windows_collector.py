import time
import sys
import csv
import io
import subprocess
from typing import Callable, Dict
from core.schema import SystemEvent

# In-memory cache for fast PID -> Process Name resolution
PID_NAME_CACHE: Dict[int, str] = {0: "System Idle Process", 4: "System"}

def get_process_name_by_pid(pid: int) -> str:
    """Resolves parent process name using cached lookups and psutil fallback."""
    if pid in PID_NAME_CACHE:
        return PID_NAME_CACHE[pid]
    try:
        import psutil
        name = psutil.Process(pid).name()
        PID_NAME_CACHE[pid] = name
        return name
    except Exception:
        return "unknown"

def stream_windows_events(
    event_callback: Callable[[SystemEvent], None],
    status_callback: Callable[[str, str], None]
):
    """
    Streams Windows process events with parent PID and parent process name resolution.
    Recovers from transient errors without exiting.
    """
    try:
        import wmi
        import pythoncom
    except ImportError as e:
        status_callback("DEGRADED", f"WMI unavailable ({e}); using tasklist polling fallback")
        _stream_tasklist_events(event_callback, status_callback)
        return

    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        watcher = c.Win32_Process.watch_for("creation")
        status_callback("HEALTHY", "WMI Event Stream Established (Lineage Tracking Active)")
    except Exception as e:
        status_callback("CRITICAL_FAILURE", f"Failed to initialize WMI watcher: {e}")
        return

    consecutive_timeouts = 0
    while True:
        try:
            p = watcher(timeout_ms=1000)
            consecutive_timeouts = 0
            
            pid = int(p.ProcessId)
            parent_pid = int(p.ParentProcessId or 0)
            proc_name = str(p.Caption or "unknown")
            
            # Update cache for future child queries
            PID_NAME_CACHE[pid] = proc_name
            parent_name = get_process_name_by_pid(parent_pid)

            event = SystemEvent(
                timestamp=time.time(),
                os_type="windows",
                pid=pid,
                parent_pid=parent_pid,
                process_name=proc_name,
                parent_process_name=parent_name,
                cmdline=str(p.CommandLine or "")
            )
            event_callback(event)

        except wmi.x_wmi_timed_out:
            consecutive_timeouts += 1
            if consecutive_timeouts % 30 == 0:
                status_callback("HEALTHY", f"Collector Heartbeat OK ({consecutive_timeouts}s idle)")
            continue
        except Exception as e:
            status_callback("DEGRADED", f"Collector Exception: {e}")
            time.sleep(1)

def _stream_tasklist_events(
    event_callback: Callable[[SystemEvent], None],
    status_callback: Callable[[str, str], None],
):
    seen_pids = _read_tasklist_pids()
    status_callback("HEALTHY", "tasklist polling fallback established")

    while True:
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=True,
            )
            current_pids = set()
            for row in csv.reader(io.StringIO(result.stdout)):
                if len(row) < 2 or not row[1].isdigit():
                    continue
                pid = int(row[1])
                current_pids.add(pid)
                if pid not in seen_pids:
                    event_callback(SystemEvent(
                        timestamp=time.time(),
                        os_type="windows",
                        pid=pid,
                        parent_pid=0,
                        process_name=row[0],
                        parent_process_name="unknown",
                        cmdline="",
                    ))
            seen_pids = current_pids
            time.sleep(1.0)
        except (OSError, subprocess.SubprocessError) as exc:
            status_callback("DEGRADED", f"tasklist polling failed: {exc}")
            time.sleep(1.0)

def _read_tasklist_pids():
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            int(row[1])
            for row in csv.reader(io.StringIO(result.stdout))
            if len(row) >= 2 and row[1].isdigit()
        }
    except (OSError, subprocess.SubprocessError):
        return set()