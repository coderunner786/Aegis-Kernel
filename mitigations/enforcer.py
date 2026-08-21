import os
import time
import signal
import ctypes
from typing import Tuple, Dict
from collections import deque

PROTECTED_BINARIES = {
    # Core OS & Subsystems
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe", "dwm.exe",
    "searchfilterhost.exe", "searchprotocolhost.exe", "searchindexer.exe",
    "conhost.exe", "runtimebroker.exe", "taskhostw.exe", "dllhost.exe",
    "mousocoreworker.exe", "wmiapsrv.exe", "backgroundtaskhost.exe",
    "sihost.exe", "smartscreen.exe", "ctfmon.exe", "securityhealthhost.exe",
    "securityhealthservice.exe", "msedgewebview2.exe",
    # Developer Tooling & Standard Browsers
    "code.exe", "git.exe", "ollamasetup.exe", "ollama.exe", "llama-server.exe",
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe",
    # Hardware Management
    "asussystemanalysis.exe", "asussystemdiagnosis.exe", "armourycrateservicestour.exe",
    # Linux Core
    "systemd", "init", "kthreadd", "systemd-journald", "dbus-daemon", "sshd"
}

PROTECTED_PIDS = {0, 1, 2, 3, 4}

class MitigationEnforcer:
    def __init__(self, max_actions_per_window: int = 3, window_seconds: float = 10.0):
        self.max_actions = max_actions_per_window
        self.window_seconds = window_seconds
        self.action_timestamps = deque()
        self.suspended_registry: Dict[int, float] = {}

    def is_rate_limited(self) -> bool:
        """Token-bucket rate limiter preventing cascading lockouts."""
        now = time.time()
        while self.action_timestamps and now - self.action_timestamps[0] > self.window_seconds:
            self.action_timestamps.popleft()
        return len(self.action_timestamps) >= self.max_actions

    def suspend_process_windows(self, pid: int) -> bool:
        """Uses NtSuspendProcess to freeze Windows execution safely."""
        try:
            PROCESS_SUSPEND_RESUME = 0x0800
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
            if not handle:
                return False
            status = ntdll.NtSuspendProcess(handle)
            kernel32.CloseHandle(handle)
            return status == 0
        except Exception:
            return False

    def resume_process_windows(self, pid: int) -> bool:
        """Uses NtResumeProcess to unfreeze a suspended Windows process."""
        try:
            PROCESS_SUSPEND_RESUME = 0x0800
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
            if not handle:
                return False
            status = ntdll.NtResumeProcess(handle)
            kernel32.CloseHandle(handle)
            return status == 0
        except Exception:
            return False

    def suspend_process_linux(self, pid: int) -> bool:
        """Uses SIGSTOP to freeze Linux execution."""
        try:
            os.kill(pid, signal.SIGSTOP)
            return True
        except Exception:
            return False

    def resume_process_linux(self, pid: int) -> bool:
        """Uses SIGCONT to resume Linux execution."""
        try:
            os.kill(pid, signal.SIGCONT)
            return True
        except Exception:
            return False

    def enforce_safeguards_and_suspend(self, pid: int, process_name: str, os_type: str) -> Tuple[bool, str]:
        clean_name = process_name.lower().strip()

        # Rule 1: Guard root / core PIDs
        if pid in PROTECTED_PIDS or pid <= 4:
            return False, "SKIPPED_PROTECTED_PID"

        # Rule 2: Guard critical binaries & tooling
        if clean_name in PROTECTED_BINARIES:
            return False, "SKIPPED_SYSTEM_ALLOWLIST"

        # Rule 3: Guard against rate limit exhaustion
        if self.is_rate_limited():
            return False, "SKIPPED_RATE_LIMIT_EXCEEDED"

        # Rule 4: Execute suspension
        if os_type == "windows":
            success = self.suspend_process_windows(pid)
        else:
            success = self.suspend_process_linux(pid)

        if success:
            self.action_timestamps.append(time.time())
            self.suspended_registry[pid] = time.time()
            return True, "PROCESS_SUSPENDED_SUCCESS"
        else:
            return False, "SUSPEND_FAILED_INSUFFICIENT_PRIVS"

    def rollback_process_suspension(self, pid: int, os_type: str) -> bool:
        if os_type == "windows":
            res = self.resume_process_windows(pid)
        else:
            res = self.resume_process_linux(pid)
        if res:
            self.suspended_registry.pop(pid, None)
        return res

# Global singleton instance for direct module calls
_enforcer = MitigationEnforcer()

def enforce_safeguards_and_suspend(pid: int, process_name: str, os_type: str) -> Tuple[bool, str]:
    return _enforcer.enforce_safeguards_and_suspend(pid, process_name, os_type)

def rollback_process_suspension(pid: int, os_type: str) -> bool:
    return _enforcer.rollback_process_suspension(pid, os_type)

def suspend_process_windows(pid: int) -> bool:
    return _enforcer.suspend_process_windows(pid)

def suspend_process_linux(pid: int) -> bool:
    return _enforcer.suspend_process_linux(pid)