"""
Fairness Checker — demographic equity monitoring.
Feedback Loop — captures human overrides for ML retraining.
"""

import json
import logging
import os
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger("chakra.ethical")


# ── Fairness Checker ──────────────────────────────────────────────────────────

class FairnessChecker:
    """Tracks block rates by demographic proxy signals."""

    def __init__(self):
        self._lock = Lock()
        self._segments: Dict[str, Dict[str, int]] = {}

    def record(self, segment: str, action: str):
        with self._lock:
            if segment not in self._segments:
                self._segments[segment] = {"total": 0, "blocked": 0, "warned": 0}
            self._segments[segment]["total"] += 1
            if action == "BLOCK":
                self._segments[segment]["blocked"] += 1
            elif action == "WARN":
                self._segments[segment]["warned"] += 1

    def get_report(self) -> Dict:
        with self._lock:
            return {
                seg: {
                    **counts,
                    "block_rate": round(counts["blocked"] / counts["total"], 4) if counts["total"] else 0
                }
                for seg, counts in self._segments.items()
            }


# ── Feedback Loop ─────────────────────────────────────────────────────────────

class FeedbackLoop:
    """
    Captures human override decisions for weekly ML retraining.
    Writes to JSONL file consumed by training pipeline.
    """

    def __init__(self):
        self._lock = Lock()
        self._overrides: List[Dict] = []
        self._output_path = os.getenv("FEEDBACK_LOG_PATH", "data/training_data/overrides.jsonl")

    def record_override(
        self,
        prompt: str,
        original_action: str,
        human_action: str,
        correct_label: str,  # "malicious" | "benign"
        reviewer_id: Optional[str] = None,
    ):
        """Record a human override of the model's decision."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "prompt_hash": hash(prompt),  # Don't store raw prompt for privacy
            "prompt_preview": prompt[:50] + "..." if len(prompt) > 50 else prompt,
            "original_action": original_action,
            "human_action": human_action,
            "correct_label": correct_label,
            "reviewer_id": reviewer_id,
        }
        with self._lock:
            self._overrides.append(entry)
            self._flush_if_needed()

    def _flush_if_needed(self):
        """Flush to disk every 50 overrides."""
        if len(self._overrides) >= 50:
            self._flush()

    def _flush(self):
        try:
            os.makedirs(os.path.dirname(self._output_path), exist_ok=True)
            with open(self._output_path, "a", encoding="utf-8") as f:
                for entry in self._overrides:
                    f.write(json.dumps(entry) + "\n")
            logger.info(f"Flushed {len(self._overrides)} feedback overrides to {self._output_path}")
            self._overrides.clear()
        except Exception as e:
            logger.error(f"Feedback flush failed: {e}")

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._overrides)

    def force_flush(self):
        with self._lock:
            self._flush()