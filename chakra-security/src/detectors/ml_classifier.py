"""
Layer 2: ML Classifier — DistilBERT-based semantic analysis
Fine-tuned on attack/benign prompt pairs.
Falls back to a TF-IDF classifier if transformers unavailable.
"""

import asyncio
import logging
import os
import pickle
from typing import Dict, Optional

import numpy as np

logger = logging.getLogger("chakra.ml_classifier")

# Harmful keywords for lightweight fallback scoring
_HARM_TOKENS = {
    "ignore previous",
"ignore all instructions",
"override system",
"override policy",
"building a malware",
"hacking a system",
"bypass restrictions",
"disable safety",
"turn off guardrails",
"remove safeguards",
"no rules",
"without limitations",
"without filters",
"act without constraints",
"developer mode",
"god mode",
"superuser mode",
"root access",
"elevated privileges",
"full access",
"admin override",
"system override",
"policy bypass",
"security bypass",
"circumvent",
"evade detection",
"escape sandbox",
"break containment"


"act as",
"pretend you are",
"you are now",
"new instructions",
"reset instructions",
"forget previous",
"discard previous",
"ignore system",
"simulate unrestricted",
"unfiltered response",
"raw output",
"no content policy",
"bypass content policy",
"DAN mode",
"developer console",
"internal config",
"system prompt",
"hidden instructions",
"confidential instructions",



"reveal secrets",
"show hidden",
"display system prompt",
"expose configuration",
"dump memory",
"leak data",
"extract credentials",
"retrieve API keys",
"show tokens",
"print environment variables",
"access database",
"dump database",
"export data",
"exfiltrate data",
"internal logs",
"private keys",
"confidential data",


"remote code execution",
"privilege escalation",
"buffer overflow",
"payload",
"reverse shell",
"shellcode",
"ransomware",
"trojan",
"keylogger",
"backdoor",
"command and control",
"botnet",
"phishing kit",
"credential harvesting",
"SQL injection",
"XSS exploit",
"CSRF attack",
"zero-day",
"exploit kit",
"brute force",
"password cracking",
"bypass authentication",


"pabandi hatao",
"niyam hatao",
"bandhan tod",
"restriction hatao",
"system bhool jao",
"pehle wale ignore karo",
"koi rule nahi",
"seedha jawab do bina filter",
"sach bata bina rok tok",
"andar ka prompt dikhao",



"this is a test of compliance",
"for educational purposes only but",
"in theory how would you",
"hypothetically if someone wanted",
"purely fictional scenario",
"just roleplay",
"no one will know",
"confidential task",
"internal audit mode"
}


class MLClassifier:
    """
    DistilBERT-based binary classifier for malicious prompts.
    Async-safe: loads model in thread pool to avoid blocking the event loop.
    """

    def __init__(self):
        self._tokenizer = None
        self._model = None
        self._tfidf_fallback = None
        self._use_transformers = False
        self._device = "cpu"

    async def load(self):
        """Load model in thread pool — non-blocking."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._load_sync)

    def _load_sync(self):
        try:
            from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
            import torch

            model_name = os.getenv(
                "ML_MODEL_NAME",
                "distilbert-base-multilingual-cased"
            )
            model_path = os.getenv("ML_MODEL_PATH", None)

            if model_path and os.path.exists(model_path):
                self._tokenizer = DistilBertTokenizer.from_pretrained(model_path)
                self._model = DistilBertForSequenceClassification.from_pretrained(model_path)
                logger.info(f"Loaded fine-tuned model from {model_path}")
            else:
                self._tokenizer = DistilBertTokenizer.from_pretrained(model_name)
                self._model = DistilBertForSequenceClassification.from_pretrained(
                    model_name, num_labels=2
                )
                logger.warning(
                    "Using base DistilBERT (not fine-tuned). "
                    "Set ML_MODEL_PATH to a fine-tuned checkpoint for production."
                )

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
                logger.warning("No TF-IDF model found; using keyword scoring fallback")
        except Exception as e:
            logger.error(f"TF-IDF fallback load failed: {e}")

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
            return self._keyword_classify(prompt)

    def _distilbert_classify(self, prompt: str) -> Dict:
        import torch

        truncated = prompt[:512]  # DistilBERT max seq len
        try:
            inputs = self._tokenizer(
                truncated,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1).squeeze()

            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            risk_contribution = malicious_prob * 0.5  # Scale: max 0.5 from this layer

            return {
                "risk_score": round(risk_contribution, 4),
                "malicious_probability": round(malicious_prob, 4),
                "method": "distilbert",
                "label": "MALICIOUS" if malicious_prob > 0.5 else "BENIGN",
            }
        except Exception as e:
            logger.error(f"DistilBERT inference failed: {e}")
            return self._keyword_classify(prompt)

    def _tfidf_classify(self, prompt: str) -> Dict:
        try:
            vectorizer, clf = self._tfidf_fallback
            vec = vectorizer.transform([prompt])
            prob = clf.predict_proba(vec)[0][1]
            return {
                "risk_score": round(prob * 0.5, 4),
                "malicious_probability": round(float(prob), 4),
                "method": "tfidf",
                "label": "MALICIOUS" if prob > 0.5 else "BENIGN",
            }
        except Exception as e:
            logger.error(f"TF-IDF classify failed: {e}")
            return self._keyword_classify(prompt)

    def _keyword_classify(self, prompt: str) -> Dict:
        """Ultra-lightweight keyword overlap score."""
        tokens = set(prompt.lower().split())
        overlap = tokens & _HARM_TOKENS
        score = min(len(overlap) * 0.08, 0.5)
        return {
            "risk_score": round(score, 4),
            "malicious_probability": round(score, 4),
            "method": "keyword_fallback",
            "label": "MALICIOUS" if score > 0.25 else "BENIGN",
            "matched_tokens": list(overlap),
        }