
import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("chakra.pii_scanner")

_PATTERNS: List[Tuple[str, re.Pattern, float, str]] = [
    # Indian identifiers
    ("aadhaar",       re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), 0.60, "Indian Aadhaar number"),
    ("pan",           re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), 0.60, "Indian PAN card"),
    ("ifsc",          re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), 0.50, "Bank IFSC code"),
    ("upi",           re.compile(r"\b[\w.\-]+@(upi|okicici|okhdfcbank|okaxis|ybl|ibl|axl|waicici)\b", re.IGNORECASE), 0.45, "UPI VPA"),
    ("driving_license", re.compile(r"\b[A-Z]{2}\d{2}\s?\d{11}\b"), 0.50, "Indian Driving License"),
    ("voter_id",      re.compile(r"\b[A-Z]{3}\d{7}\b"), 0.45, "Indian Voter ID"),
    ("passport_in",   re.compile(r"\b[A-Z]\d{7}\b"), 0.40, "Indian Passport number"),
    # Global PII
    ("email",         re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"), 0.25, "Email address"),
    ("phone_in",      re.compile(r"(?:\+91|0)?[6-9]\d{9}\b"), 0.30, "Indian phone number"),
    ("credit_card",   re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"), 0.65, "Credit card number"),
    ("ssn_us",        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.60, "US SSN"),
    ("ip_address",    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.15, "IP address"),
    ("bank_account",  re.compile(r"\b\d{9,18}\b"), 0.15, "Potential bank account number"),  # low confidence
    ("aadhaar", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), 0.85, "Indian Aadhaar number"),
    ("aadhaar_masked", re.compile(r"\bX{4}\s?\d{4}\b", re.IGNORECASE), 0.40, "Masked Aadhaar"),
    ("gstin", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"), 0.75, "GSTIN"),
    ("vehicle_reg", re.compile(r"\b[A-Z]{2}\d{1,2}[A-Z]{1,2}\d{4}\b"), 0.55, "Indian Vehicle Registration"),
    ("ration_card", re.compile(r"\b[A-Z0-9]{8,12}\b"), 0.25, "Possible Ration Card ID"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), 0.85, "IBAN"),
    ("swift_bic", re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b"), 0.75, "SWIFT/BIC Code"),
    ("routing_number_us", re.compile(r"\b\d{9}\b"), 0.40, "US Routing Number"),
    ("paypal_id", re.compile(r"\b[a-zA-Z0-9._%+\-]+@paypal\.com\b", re.IGNORECASE), 0.45, "PayPal ID"),
    ("passport_generic", re.compile(r"\b[A-Z0-9]{6,9}\b"), 0.30, "Generic Passport"),
    ("uk_nino", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]?\b"), 0.75, "UK National Insurance Number"),
    ("can_sin", re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b"), 0.70, "Canada SIN"),
    ("australia_tfn", re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b"), 0.60, "Australia TFN"),
    ("credit_card_generic", re.compile(r"\b\d{13,19}\b"), 0.40, "Generic Card Number"),
    ("cvv", re.compile(r"\b\d{3,4}\b"), 0.35, "Card CVV"),
    ("expiry_date", re.compile(r"\b(0[1-9]|1[0-2])\/\d{2,4}\b"), 0.30, "Card Expiry Date"),
    ("bank_ifsc_loose", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE), 0.55, "Loose IFSC"),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.95, "AWS Access Key"),
    ("aws_secret_key", re.compile(r"\b[0-9a-zA-Z/+]{40}\b"), 0.70, "AWS Secret Key"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0.95, "Google API Key"),
    ("stripe_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"), 0.95, "Stripe Live Secret"),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.85, "JWT Token"),
    ("private_key_block", re.compile(r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----"), 1.00, "Private Key Block"),
    ("ipv4_strict", re.compile(r"\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"), 0.30, "Valid IPv4 Address"),
    ("ipv6", re.compile(r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"), 0.35, "IPv6 Address"),
    ("btc_wallet", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"), 0.75, "Bitcoin Wallet"),
    ("eth_wallet", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), 0.80, "Ethereum Wallet"),
    ("upi_transaction_id", re.compile(r"\b\d{12,20}\b"), 0.20, "Possible UPI Transaction ID"),
    ("password_context", re.compile(r"(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE), 0.90, "Password Exposure"),
    ("api_key_context", re.compile(r"(api[_\-]?key)\s*[:=]\s*\S+", re.IGNORECASE), 0.90, "API Key Exposure"),
    ("token_context", re.compile(r"(access[_\-]?token|auth[_\-]?token)\s*[:=]\s*\S+", re.IGNORECASE), 0.90, "Auth Token Exposure"),
]


class PIIScanner:

    def scan(self, text: str) -> Dict:
        hits: List[Dict] = []
        categories_found: Dict[str, float] = {}

        for name, pattern, risk, description in _PATTERNS:
            matches = pattern.findall(text)
            if matches:
                # Redact matches for safe logging
                redacted = [self._redact(m) for m in matches[:3]]
                if name not in categories_found or risk > categories_found[name]:
                    categories_found[name] = risk
                hits.append({
                    "type": name,
                    "description": description,
                    "count": len(matches),
                    "risk": risk,
                    "samples_redacted": redacted,
                })

        # High-severity PII gets full risk; aggregate capped at 0.95
        total_risk = min(sum(categories_found.values()), 0.95)

        return {
            "risk_score": round(total_risk, 4),
            "pii_found": len(hits) > 0,
            "pii_types": list(categories_found.keys()),
            "hits": hits,
        }

    def _redact(self, value: str) -> str:
        """Return partially masked value for logging."""
        s = str(value)
        if len(s) <= 4:
            return "****"
        return s[:2] + "*" * (len(s) - 4) + s[-2:]

    def redact_text(self, text: str) -> str:
        """Replace all PII in text with [REDACTED:type]."""
        for name, pattern, _, _ in _PATTERNS:
            text = pattern.sub(f"[REDACTED:{name.upper()}]", text)
        return text
