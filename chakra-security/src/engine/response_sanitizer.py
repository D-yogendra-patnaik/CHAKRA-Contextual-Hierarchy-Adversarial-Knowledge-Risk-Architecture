"""
Response Sanitizer — redacts PII from LLM output before delivery.
"""

import re
from typing import List, Tuple

_REDACT_PATTERNS = [
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "[REDACTED:AADHAAR]"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[REDACTED:PAN]"),
    (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), "[REDACTED:IFSC]"),
    (re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"), "[REDACTED:CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
    (re.compile(r"\b[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}\b"), "[REDACTED:EMAIL]"),
    (re.compile(r"(?:\+91|0)?[6-9]\d{9}\b"), "[REDACTED:PHONE]"),
]


class ResponseSanitizer:

    def sanitize(self, text: str) -> str:
        for pattern, replacement in _REDACT_PATTERNS:
            text = pattern.sub(replacement, text)
        return text