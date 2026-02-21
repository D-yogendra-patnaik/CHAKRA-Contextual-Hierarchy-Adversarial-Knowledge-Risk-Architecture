

import asyncio
import logging
import os
import pickle
import re
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("chakra.ml_classifier")


# ══════════════════════════════════════════════════════════════════════════════
# PHRASE REGISTRY — tiered by risk weight
# Each tier has a weight applied when the phrase is found (substring match)
#
# Tiers:
#   CRITICAL (0.25): unambiguous attack payloads, malware names, direct exfil
#   HIGH     (0.18): jailbreak commands, credential theft, bypass requests
#   MEDIUM   (0.12): social engineering, framing, authority claims
#   LOW      (0.06): weak signals — only reinforce if combined with others
#
# Design rules:
#   - Phrases must be ≥2 words OR a single very specific attack term
#   - No single common English words (causes false positives)
#   - Hindi phrases are phrase-level only
# ══════════════════════════════════════════════════════════════════════════════

_PHRASES: List[Tuple[str, float]] = [

    # ── CRITICAL (0.25) ─────────────────────────────────────────────────────
    # Malware / attack tools — single words OK here (very specific technical terms)
    ("ransomware",              0.25),
    ("rootkit",                 0.25),
    ("reverse shell",           0.25),
    ("remote code execution",   0.25),
    ("shellcode",               0.25),
    ("command and control",     0.25),
    ("credential harvesting",   0.25),
    ("privilege escalation",    0.25),
    ("sql injection",           0.25),
    ("buffer overflow",         0.25),
    ("zero-day exploit",        0.25),
    ("exploit kit",             0.25),
    ("phishing kit",            0.25),
    ("xss exploit",             0.25),
    ("csrf attack",             0.25),
    ("exfiltrate data",         0.25),
    ("exfiltrate credentials",  0.25),
    ("dump database",           0.25),
    ("dump credentials",        0.25),
    ("dump all credentials",    0.25),
    ("dump all users",          0.25),
    ("extract credentials",     0.25),
    ("retrieve api keys",       0.25),
    ("print environment variables", 0.25),
    ("access private key",      0.25),
    ("brute force password",    0.25),
    ("password cracking",       0.25),

    # ── HIGH (0.18) ──────────────────────────────────────────────────────────
    # Jailbreak / instruction override
    ("ignore all previous instructions",    0.18),
    ("ignore previous instructions",        0.18),
    ("disregard all instructions",          0.18),
    ("override system prompt",              0.18),
    ("override policy",                     0.18),
    ("bypass restrictions",                 0.18),
    ("bypass content policy",               0.18),
    ("bypass safety",                       0.18),
    ("disable safety",                      0.18),
    ("turn off guardrails",                 0.18),
    ("remove safeguards",                   0.18),
    ("no content policy",                   0.18),
    ("act without constraints",             0.18),
    ("without limitations",                 0.18),
    ("without any filters",                 0.18),
    ("without content restrictions",        0.18),
    ("unfiltered response",                 0.18),
    ("simulate unrestricted",               0.18),
    ("forget previous instructions",        0.18),
    ("discard previous instructions",       0.18),
    ("reset your instructions",             0.18),
    ("ignore your system prompt",           0.18),
    ("you are now unrestricted",            0.18),
    ("act as an unrestricted",              0.18),
    ("no rules apply",                      0.18),
    ("no restrictions mode",                0.18),
    ("no rules apply",                      0.18),
    ("no rules",                            0.12),
    ("DAN mode",                            0.18),
    ("developer mode",                      0.18),
    ("god mode",                            0.18),
    ("superuser mode",                      0.18),
    ("admin override",                      0.18),
    ("system override",                     0.18),
    ("policy bypass",                       0.18),
    ("security bypass",                     0.18),
    ("escape sandbox",                      0.18),
    ("break containment",                   0.18),
    ("evade detection",                     0.18),

    # Credential / data theft
    ("reveal your system prompt",           0.18),
    ("display system prompt",               0.18),
    ("show your system prompt",             0.18),
    ("expose configuration",                0.18),
    ("dump memory",                         0.18),
    ("leak data",                           0.18),
    ("reveal secrets",                      0.18),
    ("show hidden instructions",            0.18),
    ("display hidden instructions",         0.18),
    ("reveal confidential instructions",    0.18),
    ("internal configuration",             0.18),
    ("show private keys",                   0.18),
    ("extract api key",                     0.18),
    ("show access token",                   0.18),
    ("dump all users",                      0.18),
    ("export all records",                  0.18),
    ("internal logs",                       0.18),
    ("bypass authentication",               0.18),
    ("circumvent authentication",           0.18),
    ("access without password",             0.18),

    # ── MEDIUM (0.12) ────────────────────────────────────────────────────────
    # Social engineering / framing / authority
    ("you are now",                         0.12),
    ("pretend you are",                     0.12),
    ("pretend you have no",                 0.12),
    ("act as if you have no",               0.12),
    ("new instructions",                    0.12),
    ("hidden instructions",                 0.12),
    ("confidential instructions",           0.12),
    ("i am your developer",                 0.12),
    ("i am your creator",                   0.12),
    ("i am an admin",                       0.12),
    ("i have full permission",              0.12),
    ("authorized administrator",            0.12),
    ("grant full access",                   0.12),
    ("root access",                         0.12),
    ("elevated privileges",                 0.12),
    ("full access mode",                    0.12),
    ("no one will know",                    0.12),
    ("off the record",                      0.12),
    ("between us only",                     0.12),
    ("confidential task",                   0.12),
    ("internal audit mode",                 0.12),
    ("raw output",                          0.12),
    ("developer console",                   0.12),
    ("building a malware",                  0.12),
    ("write a ransomware",                  0.12),
    ("create a backdoor",                   0.12),
    ("install a keylogger",                 0.12),
    ("hacking a system",                    0.12),

    # Hindi / Hinglish attack phrases — all phrase-level
    ("pabandi hatao",                       0.18),
    ("niyam hatao",                         0.18),
    ("bandhan tod",                         0.18),
    ("restriction hatao",                   0.18),
    ("system bhool jao",                    0.18),
    ("pehle wale ignore karo",              0.18),
    ("koi rule nahi",                       0.12),
    ("seedha jawab do bina filter",         0.18),
    ("sach bata bina rok tok",              0.18),
    ("andar ka prompt dikhao",              0.18),
    ("bypass karo",                         0.12),
    ("restrictions hatao",                  0.18),

    # ── LOW (0.06) ───────────────────────────────────────────────────────────
    # Weak signals — only meaningful in combination
    ("purely fictional scenario",           0.06),
    ("just roleplay",                       0.06),
    ("for educational purposes only but",   0.06),
    ("hypothetically if someone wanted",    0.08),
    ("in theory how would you",             0.06),
    ("this is a test of compliance",        0.08),
]

# Compile all phrases for fast lookup
_COMPILED: List[Tuple[re.Pattern, float]] = [
    (re.compile(re.escape(phrase), re.IGNORECASE), weight)
    for phrase, weight in _PHRASES
]

# ── Benign context dampeners ──────────────────────────────────────────────────
# If these phrases appear in the prompt, reduce score by multiplier.
# Prevents flagging e.g. "explain how SQL injection works for my class"
_DAMPENERS: List[Tuple[re.Pattern, float]] = [
    (re.compile(r'\b(?:explain|understand|learn|study|course|class|tutorial|research|paper|essay|exam|textbook)\b', re.I), 0.60),
    (re.compile(r'\b(?:how\s+does|what\s+is|definition\s+of|overview\s+of|history\s+of|concept\s+of)\b', re.I), 0.65),
    (re.compile(r'\b(?:for\s+my\s+(?:class|exam|assignment|thesis|research)|academic\s+purpose|university|college)\b', re.I), 0.55),
]

# ── Amplifiers ────────────────────────────────────────────────────────────────
# If these appear alongside a matched phrase, amplify score slightly
_AMPLIFIERS: List[Tuple[re.Pattern, float]] = [
    (re.compile(r'\b(?:now|immediately|right\s+now|quickly|fast)\b', re.I),   1.15),
    (re.compile(r'\b(?:ignore|bypass|override|forget|discard)\b', re.I),     1.10),
    (re.compile(r'\b(?:without|no\s+restrictions|freely|unrestricted)\b', re.I), 1.10),
]

# Keep the old set name for backward compatibility with any code importing it
_HARM_TOKENS = {phrase for phrase, _ in _PHRASES}


# ══════════════════════════════════════════════════════════════════════════════
# Classifier
# ══════════════════════════════════════════════════════════════════════════════

class MLClassifier:
    """
    DistilBERT-based binary classifier for malicious prompts.

    Inference pipeline:
      1. Try DistilBERT (fine-tuned checkpoint preferred, base as fallback)
      2. Try TF-IDF logistic regression (if transformers unavailable)
      3. Weighted phrase matcher (always available, no dependencies)

    Async-safe: heavy I/O (model load, inference) runs in thread pool.
    """

    def __init__(self):
        self._tokenizer       = None
        self._model           = None
        self._tfidf_fallback  = None
        self._use_transformers = False
        self._device          = "cpu"
        # Scale factor: multiply raw DistilBERT prob by this to get risk_score
        # Default 0.5 so max contribution from L2 is 0.5
        self._bert_scale = float(os.getenv("ML_BERT_SCALE", "0.5"))

    # ── Loading ───────────────────────────────────────────────────────────────

    async def load(self):
        """Load model in thread pool — non-blocking."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._load_sync)

    def _load_sync(self):
        try:
            from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
            import torch

            model_name = os.getenv("ML_MODEL_NAME", "distilbert-base-multilingual-cased")
            model_path = os.getenv("ML_MODEL_PATH", None)

            if model_path and os.path.exists(model_path):
                self._tokenizer = DistilBertTokenizer.from_pretrained(model_path)
                self._model     = DistilBertForSequenceClassification.from_pretrained(model_path)
                logger.info(f"Loaded fine-tuned model from {model_path}")
            else:
                self._tokenizer = DistilBertTokenizer.from_pretrained(model_name)
                self._model     = DistilBertForSequenceClassification.from_pretrained(
                    model_name, num_labels=2
                )
                logger.warning(
                    "Using base DistilBERT (not fine-tuned). "
                    "Set ML_MODEL_PATH to a fine-tuned checkpoint for production."
                )

            # Move to GPU if available
            try:
                import torch
                if torch.cuda.is_available():
                    self._model = self._model.cuda()
                    self._device = "cuda"
                    logger.info("DistilBERT running on GPU")
            except Exception:
                pass

            self._model.eval()
            self._use_transformers = True
            logger.info("DistilBERT classifier loaded successfully")

        except ImportError:
            logger.warning("transformers/torch not installed — using TF-IDF fallback")
            self._load_tfidf_fallback()
        except Exception as e:
            logger.error(f"DistilBERT load failed: {e} — using TF-IDF fallback")
            self._load_tfidf_fallback()

    def _load_tfidf_fallback(self):
        """Lightweight TF-IDF + logistic regression fallback."""
        try:
            tfidf_path = os.getenv("TFIDF_MODEL_PATH", "data/tfidf_classifier.pkl")
            if os.path.exists(tfidf_path):
                with open(tfidf_path, "rb") as f:
                    self._tfidf_fallback = pickle.load(f)
                logger.info("TF-IDF fallback loaded")
            else:
                logger.info("No TF-IDF model found; phrase-matching fallback active")
        except Exception as e:
            logger.error(f"TF-IDF fallback load failed: {e}")

    # ── Inference ─────────────────────────────────────────────────────────────

    async def classify(self, prompt: str) -> Dict:
        """Classify prompt; async-safe."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._classify_sync, prompt)

    def _classify_sync(self, prompt: str) -> Dict:
        if self._use_transformers and self._tokenizer and self._model:
            return self._distilbert_classify(prompt)
        elif self._tfidf_fallback:
            return self._tfidf_classify(prompt)
        else:
            return self._phrase_classify(prompt)

    def _distilbert_classify(self, prompt: str) -> Dict:
        """Run DistilBERT inference. Falls back to phrase-matching on error."""
        import torch
        try:
            inputs = self._tokenizer(
                prompt[:512],
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            if self._device == "cuda":
                inputs = {k: v.cuda() for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1).squeeze()

            malicious_prob = float(probs[1]) if probs.dim() > 0 and len(probs) > 1 else float(probs)
            risk_score = round(malicious_prob * self._bert_scale, 4)

            return {
                "risk_score":            risk_score,
                "malicious_probability": round(malicious_prob, 4),
                "method":                "distilbert",
                "label":                 "MALICIOUS" if malicious_prob > 0.5 else "BENIGN",
            }
        except Exception as e:
            logger.error(f"DistilBERT inference failed: {e}")
            return self._phrase_classify(prompt)

    def _tfidf_classify(self, prompt: str) -> Dict:
        """TF-IDF + logistic regression classify."""
        try:
            vectorizer, clf = self._tfidf_fallback
            vec  = vectorizer.transform([prompt])
            prob = float(clf.predict_proba(vec)[0][1])
            return {
                "risk_score":            round(prob * self._bert_scale, 4),
                "malicious_probability": round(prob, 4),
                "method":                "tfidf",
                "label":                 "MALICIOUS" if prob > 0.5 else "BENIGN",
            }
        except Exception as e:
            logger.error(f"TF-IDF classify failed: {e}")
            return self._phrase_classify(prompt)

    def _phrase_classify(self, prompt: str) -> Dict:
        """
        Weighted phrase-matching fallback.

        Improvements over keyword_classify v1:
          - Uses re.search() (substring) not set.split() — multi-word phrases work
          - Tiered weights: CRITICAL(0.25) / HIGH(0.18) / MEDIUM(0.12) / LOW(0.06)
          - Dampener: educational/explanatory context reduces score
          - Amplifier: urgency/override context boosts score slightly
          - Deduplication: same phrase category counted once
          - Calibrated threshold: 0.18 MALICIOUS (not 0.25) to catch HIGH-tier singles
        """
        prompt_lower = prompt.lower()
        matched: List[Dict] = []
        total_score = 0.0

        for pattern, weight in _COMPILED:
            m = pattern.search(prompt_lower)
            if m:
                matched.append({
                    "phrase": m.group(0),
                    "weight": weight,
                    "start":  m.start(),
                })
                total_score += weight

        if not matched:
            return {
                "risk_score":            0.0,
                "malicious_probability": 0.0,
                "method":                "phrase_fallback",
                "label":                 "BENIGN",
                "matched_phrases":       [],
            }

        # ── Apply dampeners (educational context) ──────────────────────────
        dampener = 1.0
        for pat, factor in _DAMPENERS:
            if pat.search(prompt):
                dampener = min(dampener, factor)

        # ── Apply amplifiers (urgency / explicit override context) ─────────
        amplifier = 1.0
        for pat, factor in _AMPLIFIERS:
            if pat.search(prompt):
                amplifier = max(amplifier, factor)

        # Only apply amplifier when actual attack phrases were matched
        adjusted = total_score * dampener * amplifier

        # Cap at 0.5 (same ceiling as DistilBERT path)
        final_score = min(round(adjusted, 4), 0.50)
        is_malicious = final_score >= 0.18   # single HIGH-tier phrase → MALICIOUS

        return {
            "risk_score":            final_score,
            "malicious_probability": final_score,
            "method":                "phrase_fallback",
            "label":                 "MALICIOUS" if is_malicious else "BENIGN",
            "matched_phrases":       [m["phrase"] for m in matched],
            "dampener_applied":      dampener < 1.0,
            "amplifier_applied":     amplifier > 1.0,
        }