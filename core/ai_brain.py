import math
import os
import pickle
import re
import sys
from typing import List, Tuple
import numpy as np

from core.schema import SystemEvent

# Known high-risk adversarial tokens (MITRE ATT&CK T1059, T1027, T1218, T1105)
SUSPICIOUS_TOKENS = {
    "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
    "-nop", "-noprofile", "-noni", "-noninteractive",
    "downloadstring", "downloadfile", "iex", "invoke-expression",
    "invoke-webrequest", "bypass", "bitstransfer", "certutil",
    "vssadmin", "mimikatz", "rundll32", "mshta", "wscript.shell"
}

# Core system processes that run as background daemons
SYSTEM_DAEMONS = {
    "svchost.exe", "conhost.exe", "backgroundtaskhost.exe", 
    "filecoauth.exe", "runtimebroker.exe", "taskhostw.exe", 
    "searchhost.exe", "explorer.exe", "services.exe", "csrss.exe"
}

# Trusted developer utilities
DEV_TOOLS = {
    "git.exe", "code.exe", "python.exe", "node.exe", 
    "cargo.exe", "rustc.exe", "pip.exe", "pytest.exe"
}

# Interpreters capable of executing scripts
SCRIPT_INTERPRETERS = {
    "powershell.exe", "cmd.exe", "wscript.exe", 
    "cscript.exe", "mshta.exe", "bash.exe", "sh.exe"
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a given string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(process_name: str, cmdline: str) -> List[float]:
    """
    Extracts numerical feature vectors from process name and command-line execution string.
    """
    proc = (process_name or "").lower()
    cmd = (cmdline or "").lower()

    cmd_len = float(len(cmd))
    entropy = calculate_shannon_entropy(cmd)

    # 1. Suspicious token keyword matching
    token_hits = sum(1 for token in SUSPICIOUS_TOKENS if token in cmd)

    # 2. Ratio of special characters (common in script obfuscation / piping)
    special_chars = len(re.findall(r"[\^\|\&\;\$\`\<\>\(\)\{\}\%]", cmd))
    special_ratio = (special_chars / cmd_len) if cmd_len > 0 else 0.0

    # 3. Base64 payload detection (long uninterrupted alphanumeric strings)
    has_b64_blob = 1.0 if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", cmdline or "") else 0.0

    # 4. Binary category flags
    is_interpreter = 1.0 if proc in SCRIPT_INTERPRETERS else 0.0
    is_dev = 1.0 if proc in DEV_TOOLS else 0.0
    is_daemon = 1.0 if proc in SYSTEM_DAEMONS else 0.0

    return [
        cmd_len,
        entropy,
        float(token_hits),
        special_ratio,
        has_b64_blob,
        is_interpreter,
        is_dev,
        is_daemon,
    ]


def get_model_file_path(filename: str) -> str:
    """
    Resolves model artifact paths whether running in development
    or unpacked inside a PyInstaller binary.
    """
    if hasattr(sys, "_MEIPASS"):
        bundle_path = os.path.join(sys._MEIPASS, "models", filename)
        if os.path.exists(bundle_path):
            return bundle_path

    local_path = os.path.join("models", filename)
    if os.path.exists(local_path):
        return local_path

    # Fallback to parent directory models if running from core/
    alt_path = os.path.join(os.path.dirname(__file__), "..", "models", filename)
    return alt_path


class AIEvaluator:
    """
    Inference engine that evaluates runtime system events using
    feature extraction and an Isolation Forest anomaly model.
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_models()

    def _load_models(self):
        model_path = get_model_file_path("isolation_forest.pkl")
        scaler_path = get_model_file_path("scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
            except Exception as e:
                print(f"[!] Warning: Failed to load ML model artifacts: {e}")
                self.model = None
                self.scaler = None
        else:
            self.model = None
            self.scaler = None

    def score_event(self, event: SystemEvent) -> Tuple[bool, float]:
        proc_name = (event.process_name or "").lower()
        cmdline = event.cmdline or ""
        cmd_lower = cmdline.lower()

        # 0. CRITICAL: Prevent Infinite Notification Feedback Loop
        # Ignore Aegis's own internal toast notification worker processes
        if "windows.ui.notifications" in cmd_lower or "aegis runtime defense" in cmd_lower or "aegis alert" in cmd_lower:
            return False, 0.01

        # 1. Fast Override: Known High-Risk Adversarial Flags
        if any(tok in cmd_lower for tok in ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex("]):
            return True, 0.88

        # 2. Fast Override: Benign Developer Tools without payload flags
        if proc_name in DEV_TOOLS and ("-enc" not in cmd_lower and "download" not in cmd_lower):
            return False, 0.12

        # 3. Model Inference via decision_function
        features = extract_features(event.process_name, cmdline)

        if self.model is not None and self.scaler is not None:
            try:
                feats_scaled = self.scaler.transform([features])
                df_val = self.model.decision_function(feats_scaled)[0]
                normalized_score = float(1.0 / (1.0 + np.exp(df_val * 16.0)))
            except Exception:
                normalized_score = 0.15
        else:
            token_hits = sum(1 for token in SUSPICIOUS_TOKENS if token in cmd_lower)
            entropy = calculate_shannon_entropy(cmdline)
            normalized_score = min(0.10 + (token_hits * 0.35) + (entropy * 0.04), 0.95)

        # Baseline adjustment for trusted system daemons
        if proc_name in SYSTEM_DAEMONS and normalized_score < 0.75:
            normalized_score = min(normalized_score, 0.12)

        normalized_score = float(np.clip(normalized_score, 0.05, 0.98))
        is_anomaly = normalized_score >= 0.75
        return is_anomaly, normalized_score