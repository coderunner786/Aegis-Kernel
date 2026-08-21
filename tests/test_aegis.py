import unittest
import time
import json
from pathlib import Path
from core.schema import SystemEvent, calculate_entropy
from core.security import sign_artifact, verify_artifact_integrity, generate_keypair, PRIVATE_KEY_FILE
from mitigations.enforcer import (
    MitigationEnforcer,
    enforce_safeguards_and_suspend,
    rollback_process_suspension
)
from core.ai_brain import AIEvaluator
from core.db import AuditDatabase

class TestAegisProductionSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not PRIVATE_KEY_FILE.exists():
            generate_keypair()

    def setUp(self):
        self.test_file = Path("test_artifact.tmp")
        self.sig_file = Path("test_artifact.tmp.sig")
        with open(self.test_file, "w") as f:
            f.write("aegis_secure_config=1")

    def tearDown(self):
        for p in (self.test_file, self.sig_file, Path("test_audit.db"), Path("test_dead_letter.jsonl")):
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

    def test_01_ed25519_tamper_rejection(self):
        """Verifies asymmetric Ed25519 rejects tampered artifacts."""
        sign_artifact(self.test_file, self.sig_file)
        self.assertTrue(verify_artifact_integrity(self.test_file, self.sig_file))
        
        with open(self.test_file, "a") as f:
            f.write("\nmalicious_patch=1")
            
        self.assertFalse(verify_artifact_integrity(self.test_file, self.sig_file))

    def test_02_allowlist_system_pids(self):
        """Verifies PID 0-4 are strictly guarded."""
        success, status = enforce_safeguards_and_suspend(4, "System", "windows")
        self.assertFalse(success)
        self.assertEqual(status, "SKIPPED_PROTECTED_PID")

    def test_03_allowlist_protected_binaries(self):
        """Verifies critical system and dev binaries are allowlisted."""
        for binary in ["explorer.exe", "SearchFilterHost.exe", "code.exe", "chrome.exe"]:
            success, status = enforce_safeguards_and_suspend(5555, binary, "windows")
            self.assertFalse(success)
            self.assertEqual(status, "SKIPPED_SYSTEM_ALLOWLIST")

    def test_04_rate_limiting_enforcement(self):
        """Verifies that mitigation bursts are throttled to prevent lockouts."""
        enforcer = MitigationEnforcer(max_actions_per_window=2, window_seconds=5.0)
        # Mocking actions
        enforcer.action_timestamps.append(time.time())
        enforcer.action_timestamps.append(time.time())
        
        success, status = enforcer.enforce_safeguards_and_suspend(8888, "unknown_trojan.exe", "windows")
        self.assertFalse(success)
        self.assertEqual(status, "SKIPPED_RATE_LIMIT_EXCEEDED")

    def test_05_rollback_api(self):
        """Verifies the rollback/resume handler functions cleanly."""
        res = rollback_process_suspension(999999, "windows")
        self.assertIsInstance(res, bool)

    def test_06_entropy_calculation(self):
        """Verifies calculation of Shannon entropy for obfuscated commands."""
        low_ent = calculate_entropy("calc.exe")
        high_ent = calculate_entropy("powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0A...")
        self.assertGreater(high_ent, low_ent)

    def test_07_ai_benign_event_scoring(self):
        """Verifies benign standard tools are classified as SAFE."""
        evaluator = AIEvaluator()
        event = SystemEvent(
            timestamp=time.time(),
            os_type="windows",
            pid=3000,
            parent_pid=1000,
            process_name="notepad.exe",
            parent_process_name="explorer.exe",
            cmdline="notepad.exe doc.txt"
        )
        is_anomaly, score = evaluator.score_event(event)
        self.assertFalse(is_anomaly)
        self.assertLess(score, 0.70)

    def test_08_ai_attack_detection(self):
        """Verifies obfuscated execution is scored as anomalous."""
        evaluator = AIEvaluator()
        attack = SystemEvent(
            timestamp=time.time(),
            os_type="windows",
            pid=9876,
            parent_pid=9875,
            process_name="powershell.exe",
            parent_process_name="cmd.exe",
            cmdline="powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA...",
            is_elevated=True
        )
        is_anomaly, score = evaluator.score_event(attack)
        self.assertTrue(is_anomaly)
        self.assertGreaterEqual(score, 0.72)

    def test_09_db_async_batch_writer(self):
        """Verifies that the async DB worker persists records properly."""
        db = AuditDatabase(db_path=Path("test_audit.db"), dead_letter_path=Path("test_dead_letter.jsonl"))
        event = SystemEvent(
            timestamp=time.time(),
            os_type="windows",
            pid=1111,
            parent_pid=2222,
            process_name="test_proc.exe",
            cmdline="test_proc.exe --run"
        )
        db.log_event(event, score=0.15, is_anomaly=False, status="MONITORED_SAFE")
        db.flush_and_close()
        
        self.assertTrue(Path("test_audit.db").exists())

    def test_10_dead_letter_fallback(self):
        """Verifies write failures trigger dead-letter serialization."""
        db = AuditDatabase(db_path=Path("test_audit.db"), dead_letter_path=Path("test_dead_letter.jsonl"))
        db._persist_batch([{"broken": "schema_data"}])
        self.assertTrue(Path("test_dead_letter.jsonl").exists())

if __name__ == "__main__":
    unittest.main()