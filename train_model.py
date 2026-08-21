import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
from pathlib import Path
from core.security import sign_artifact

def build_mitre_dataset():
    np.random.seed(42)
    n_normal = 10000

    # 1. Real-world Baseline Data
    # Schema: [is_elevated, name_len, cmdline_len, has_token, pid_delta, entropy, is_parent_shell]
    elevated_norm = np.random.choice([0.0, 1.0], size=(n_normal, 1), p=[0.85, 0.15])
    name_len_norm = np.random.normal(loc=12.0, scale=4.0, size=(n_normal, 1)).clip(3, 30)
    
    # Allow command line lengths up to 350 for normal developer/OS paths (VSCode, node, GUIDs)
    cmd_len_norm = np.random.exponential(scale=70.0, size=(n_normal, 1)).clip(0, 400)
    tokens_norm = np.zeros((n_normal, 1))
    pid_delta_norm = np.random.exponential(scale=3000.0, size=(n_normal, 1)).clip(50, 40000)
    
    # Normal entropy range (allowing paths and GUIDs up to 4.5)
    entropy_norm = np.random.normal(loc=3.5, scale=0.6, size=(n_normal, 1)).clip(0.0, 4.6)
    parent_shell_norm = np.random.choice([0.0, 1.0], size=(n_normal, 1), p=[0.70, 0.30])

    normal_data = np.hstack([
        elevated_norm, name_len_norm, cmd_len_norm, tokens_norm,
        pid_delta_norm, entropy_norm, parent_shell_norm
    ])

    # 2. Attack Data (Extreme entropy > 5.0, suspicious tokens, heavy payload sizing)
    n_attack = 350
    elevated_att = np.random.choice([0.0, 1.0], size=(n_attack, 1), p=[0.20, 0.80])
    name_len_att = np.random.choice([7.0, 8.0, 10.0, 14.0], size=(n_attack, 1))
    cmd_len_att = np.random.normal(loc=550.0, scale=120.0, size=(n_attack, 1)).clip(250, 2000)
    tokens_att = np.ones((n_attack, 1))
    pid_delta_att = np.random.uniform(low=10.0, high=800.0, size=(n_attack, 1))
    entropy_att = np.random.normal(loc=5.6, scale=0.4, size=(n_attack, 1)).clip(5.0, 7.0)
    parent_shell_att = np.ones((n_attack, 1))

    attack_data = np.hstack([
        elevated_att, name_len_att, cmd_len_att, tokens_att,
        pid_delta_att, entropy_att, parent_shell_att
    ])

    dataset = np.vstack([normal_data, attack_data])
    # Match SystemEvent.to_feature_vector(): runtime uses log-scaled lengths.
    dataset[:, 2] = np.log1p(dataset[:, 2])
    dataset[:, 4] = np.log1p(dataset[:, 4])
    return dataset

def train_and_sign_model():
    project_root = Path(__file__).resolve().parent
    models_dir = project_root / "models"
    models_dir.mkdir(exist_ok=True)
    dataset = build_mitre_dataset()

    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        max_samples=0.8,
        random_state=42
    )
    model.fit(dataset)

    model_path = models_dir / "isolation_forest.pkl"
    sig_path = models_dir / "isolation_forest.pkl.sig"

    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    sign_artifact(model_path, sig_path)
    print(f"[+] Re-trained on {len(dataset)} balanced telemetry vectors.")
    print(f"[+] Re-signed artifact -> {sig_path}")

if __name__ == "__main__":
    train_and_sign_model()