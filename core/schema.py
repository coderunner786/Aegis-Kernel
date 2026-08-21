from pydantic import BaseModel
from typing import Optional
import math

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum(
        (text.count(c) / len(text)) * math.log2(text.count(c) / len(text))
        for c in set(text)
    )

class SystemEvent(BaseModel):
    timestamp: float
    os_type: str
    pid: int
    parent_pid: int
    process_name: str
    cmdline: str
    parent_process_name: str = "unknown"
    is_elevated: bool = False
    source_ip: Optional[str] = None
    dest_port: Optional[int] = None

    def to_feature_vector(self) -> list:
        suspicious_tokens = [
            "powershell", "cmd.exe", "sh", "bash", "curl", "wget", 
            "mshta", "certutil", "-enc", "-encodedcommand", "downloadstring", 
            "bypass", "wscript", "cscript", "rundll32", "regsvr32"
        ]
        
        lower_cmd = self.cmdline.lower()
        lower_name = self.process_name.lower()
        lower_parent = self.parent_process_name.lower()
        
        has_token = 1.0 if any(tok in lower_cmd or tok in lower_name for tok in suspicious_tokens) else 0.0
        
        parent_shells = {"cmd.exe", "powershell.exe", "bash", "sh", "explorer.exe"}
        is_parent_shell = 1.0 if lower_parent in parent_shells else 0.0
        
        entropy = calculate_entropy(self.cmdline)
        
        # Use log scale so 800+ character browser commands don't blow up the model
        cmd_len = float(len(self.cmdline))
        scaled_cmd_len = math.log1p(cmd_len)  # log(1 + x)
        
        pid_delta = float(abs(self.pid - self.parent_pid)) if self.parent_pid > 0 else 1000.0
        scaled_pid_delta = math.log1p(pid_delta)

        return [
            1.0 if self.is_elevated else 0.0,
            float(len(self.process_name)),
            scaled_cmd_len,
            has_token,
            scaled_pid_delta,
            entropy,
            is_parent_shell
        ]