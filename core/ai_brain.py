import numpy as np
import pickle
import sys
import warnings
from pathlib import Path
from core.schema import SystemEvent
from core.security import verify_artifact_integrity

class SecurityError(Exception):
    pass

def get_bundle_path(relative_path: str) -> Path:
    if hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS) / relative_path
    project_path = Path(__file__).resolve().parent.parent / relative_path
    return project_path if project_path.exists() else Path(relative_path)

class AIEvaluator:
    def __init__(self, model_path="models/isolation_forest.pkl"):
        self.model_path = get_bundle_path(model_path)
        self.sig_path = get_bundle_path(f"{model_path}.sig")
        
        if not verify_artifact_integrity(self.model_path, self.sig_path):
            raise SecurityError(
                f"[CRITICAL] Asymmetric Ed25519 signature mismatch or missing signature: {self.model_path}. "
                "Possible unauthorized model tampering detected."
            )
            
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)

    def score_event(self, event: SystemEvent) -> tuple[bool, float]:
        features = np.array([event.to_feature_vector()])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            prediction = self.model.predict(features)[0]
            raw_score = self.model.decision_function(features)[0]

        # Normalized base confidence
        base_confidence = float(np.clip(0.5 - (raw_score * 2.0), 0.0, 1.0))
        
        lower_cmd = event.cmdline.lower()
        has_token = any(tok in lower_cmd for tok in [
            "-enc", "-encodedcommand", "downloadstring", "bypass", "invoke-expression", "iex"
        ])
        
        # High-entropy + attack signature rule
        if has_token and features[0][5] > 4.5:  # index 5 is Shannon entropy
            confidence = max(base_confidence, 0.88)
            is_anomaly = True
        else:
            confidence = base_confidence
            is_anomaly = (prediction == -1) and (confidence >= 0.72)
            
        return is_anomaly, confidence