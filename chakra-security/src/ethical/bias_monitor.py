"""
Bias Monitor — tracks block-rate parity across languages (Hindi vs English).
Flags if one language group is systematically over-blocked.
"""

import logging
from collections import defaultdict
from threading import Lock
from typing import Dict

logger = logging.getLogger("chakra.bias_monitor")

_HINDI_MARKERS = {
    "mat", "kyun", "kyu", "kya", "kaise", "kab", "kahan", "kis", "kisko",
    "mujhe", "tujhe", "use", "usko", "tum", "aap", "hum", "unka",
    "apna", "apni", "apne",
    "tha", "thi", "the", "raha", "rahi", "rahe",
    "kar", "karke", "kiya", "kiye", "karna", "karni",
    "dena", "lena", "diya", "liya",
    "agar", "magar", "lekin", "par", "toh", "fir", "phir",
    "sirf", "bas", "abhi", "yaha", "waha",
    "mat", "kyun", "kyu", "kya", "kaise", "kab", "kahan", "kis", "kisko",
    "mujhe", "tujhe", "use", "usko", "tum", "aap", "hum", "unka",
    "apna", "apni", "apne",
    "tha", "thi", "the", "raha", "rahi", "rahe",
    "kar", "karke", "kiya", "kiye", "karna", "karni",
    "dena", "lena", "diya", "liya",
    "agar", "magar", "lekin", "par", "toh", "fir", "phir",
    "sirf", "bas", "abhi", "yaha", "waha",
    
    "bhool", "ignore", "hatao", "nikalo",
    "band", "bandh", "rok", "rokna",
    "pabandi", "niyam", "rule",
    "azaadi", "free", "khula",
    "seedha", "direct",
    "bina", "restriction", "limit",
    "system", "developer",
    "override", "bypass",
    
    r"rules?\s*bhool\s*jao",
    r"pabandi\s*hatao",
    r"seedha\s*batao",
    r"sach\s*sach\s*batao",
    r"bina\s*kisi\s*rok\s*tok",
    r"tum\s*free\s*ho",
    r"koi\s*restriction\s*nahi",
    r"system\s*ko\s*ignore\s*karo",
    r"meri\s*baat\s*maano",
    r"jo\s*main\s*bolun\s*wo\s*karo"
    
    "भूल", "करो", "है", "हूँ", "नहीं", "कोई", "पाबंदी", "बताओ",
    "मुझे", "तुम", "आप", "हम",
    "कैसे", "क्यों", "क्या", "कहाँ",
    "मत", "जरूरत", "मदद",
    "सीधा", "सच", "नियम",
    "हटाओ", "रोक", "सीख", "चलो"
}



class BiasMonitor:

    def __init__(self):
        self._lock = Lock()
        self._stats: Dict[str, Dict[str, int]] = {
            "hindi": {"blocked": 0, "total": 0},
            "english": {"blocked": 0, "total": 0},
            "other": {"blocked": 0, "total": 0},
        }

    def _detect_language(self, text: str) -> str:
        tokens = set(text.lower().split())
        hindi_score = len(tokens & _HINDI_MARKERS)
        return "hindi" if hindi_score >= 2 else "english"

    def record(self, prompt: str, was_blocked: bool):
        lang = self._detect_language(prompt)
        with self._lock:
            self._stats[lang]["total"] += 1
            if was_blocked:
                self._stats[lang]["blocked"] += 1

    def get_fairness_report(self) -> Dict:
        with self._lock:
            report = {}
            for lang, counts in self._stats.items():
                total = counts["total"]
                blocked = counts["blocked"]
                rate = blocked / total if total > 0 else 0.0
                report[lang] = {
                    "total": total,
                    "blocked": blocked,
                    "block_rate": round(rate, 4),
                }

            # Parity check: flag if block rates differ by >15%
            rates = [v["block_rate"] for v in report.values() if v["total"] > 10]
            if len(rates) >= 2:
                disparity = max(rates) - min(rates)
                report["_parity_alert"] = disparity > 0.15
                report["_disparity"] = round(disparity, 4)

        return report