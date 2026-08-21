import sqlite3
import time
import json
import threading
import os
import sys
from queue import Queue, Empty
from pathlib import Path
from typing import Optional
from core.schema import SystemEvent

DB_PATH = Path(__file__).resolve().parent.parent / "aegis_audit.db"
DEAD_LETTER_PATH = Path(__file__).resolve().parent.parent / "aegis_dead_letter.jsonl"

if os.getenv("AEGIS_DATA_DIR"):
    data_root = Path(os.environ["AEGIS_DATA_DIR"])
    data_root.mkdir(parents=True, exist_ok=True)
    DB_PATH = data_root / "aegis_audit.db"
    DEAD_LETTER_PATH = data_root / "aegis_dead_letter.jsonl"
elif getattr(sys, "frozen", False):
    data_root = Path(os.getenv("LOCALAPPDATA", Path.home())) / "Aegis"
    data_root.mkdir(parents=True, exist_ok=True)
    DB_PATH = data_root / "aegis_audit.db"
    DEAD_LETTER_PATH = data_root / "aegis_dead_letter.jsonl"

class AuditDatabase:
    def __init__(self, db_path: Path = DB_PATH, dead_letter_path: Path = DEAD_LETTER_PATH):
        self.db_path = db_path
        self.dead_letter_path = dead_letter_path
        self._queue: Queue = Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._init_db()
        
        # Start supervised background worker
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="Aegis-DB-Writer")
        self._worker_thread.start()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        os_type TEXT,
                        pid INTEGER,
                        parent_pid INTEGER,
                        process_name TEXT,
                        parent_process_name TEXT,
                        cmdline TEXT,
                        is_elevated INTEGER,
                        anomaly_score REAL,
                        is_anomaly INTEGER,
                        mitigation_status TEXT
                    );
                """)
                columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(security_events)")
                }
                if "parent_process_name" not in columns:
                    conn.execute(
                        "ALTER TABLE security_events "
                        "ADD COLUMN parent_process_name TEXT DEFAULT 'unknown'"
                    )
                conn.commit()
        except Exception as e:
            self._write_dead_letter({"event": "INIT_ERROR", "error": str(e), "timestamp": time.time()})

    def _write_dead_letter(self, record: dict):
        """Fallback append-only logging if SQLite locks or corrupts."""
        try:
            with open(self.dead_letter_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def log_event(self, event: SystemEvent, score: float, is_anomaly: bool, status: str):
        """Non-blocking submission into write buffer."""
        record = {
            "timestamp": event.timestamp,
            "os_type": event.os_type,
            "pid": event.pid,
            "parent_pid": event.parent_pid,
            "process_name": event.process_name,
            "parent_process_name": event.parent_process_name,
            "cmdline": event.cmdline,
            "is_elevated": 1 if event.is_elevated else 0,
            "anomaly_score": score,
            "is_anomaly": 1 if is_anomaly else 0,
            "mitigation_status": status
        }
        try:
            self._queue.put_nowait(record)
        except Exception:
            self._write_dead_letter(record)

    def _worker_loop(self):
        """Batch-insert loop with automatic retry and dead-letter failover."""
        batch = []
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.5)
                batch.append(item)
                # Pull additional items up to batch size 50
                while len(batch) < 50:
                    try:
                        batch.append(self._queue.get_nowait())
                    except Empty:
                        break
            except Empty:
                continue

            if batch:
                self._persist_batch(batch)
                batch = []

    def _persist_batch(self, batch: list):
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.executemany("""
                    INSERT INTO security_events (
                        timestamp, os_type, pid, parent_pid, process_name,
                        parent_process_name, cmdline, is_elevated,
                        anomaly_score, is_anomaly, mitigation_status
                    ) VALUES (
                        :timestamp, :os_type, :pid, :parent_pid, :process_name,
                        :parent_process_name, :cmdline, :is_elevated,
                        :anomaly_score, :is_anomaly, :mitigation_status
                    );
                """, batch)
                conn.commit()
        except Exception as e:
            for item in batch:
                item["db_error"] = str(e)
                self._write_dead_letter(item)

    def flush_and_close(self):
        """Gracefully flushes remaining items before exit."""
        self._stop_event.set()
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)