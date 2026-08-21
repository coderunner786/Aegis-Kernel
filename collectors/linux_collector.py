import time
import os
from typing import Callable, Tuple
from core.schema import SystemEvent

def get_linux_process_lineage(pid: int) -> Tuple[int, str]:
    """
    Parses /proc/[pid]/stat to extract the true parent PID (PPID)
    and resolves the parent's process name.
    """
    ppid = 0
    parent_name = "unknown"
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat_content = f.read().strip()
            # The executable name is inside parentheses (which may contain spaces)
            # Find the closing parenthesis to safely extract fields after it
            rparen_idx = stat_content.rfind(')')
            if rparen_idx != -1:
                fields_after_comm = stat_content[rparen_idx + 2:].split()
                # field 4 in stat is index 1 after comm (state is 0, ppid is 1)
                ppid = int(fields_after_comm[1])
                
        if ppid > 0:
            with open(f"/proc/{ppid}/comm", "r") as f:
                parent_name = f.read().strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
        pass

    return ppid, parent_name

def is_linux_process_elevated(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return line.split()[1] == "0"
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
        pass
    return False

def stream_linux_events(callback: Callable[[SystemEvent], None]):
    """Streams Linux process executions with full parent lineage."""
    seen_pids = set(os.listdir('/proc'))

    while True:
        try:
            current_pids = set(os.listdir('/proc'))
            new_pids = [p for p in current_pids - seen_pids if p.isdigit()]
            seen_pids = current_pids

            for pid_str in new_pids:
                pid = int(pid_str)
                try:
                    with open(f"/proc/{pid}/cmdline", "r") as f:
                        cmd = f.read().replace('\0', ' ').strip()
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip()

                    parent_pid, parent_name = get_linux_process_lineage(pid)

                    event = SystemEvent(
                        timestamp=time.time(),
                        os_type="linux",
                        pid=pid,
                        parent_pid=parent_pid,
                        process_name=comm,
                        parent_process_name=parent_name,
                        cmdline=cmd,
                        is_elevated=is_linux_process_elevated(pid)
                    )
                    callback(event)
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
            time.sleep(0.05)
        except Exception:
            time.sleep(1)