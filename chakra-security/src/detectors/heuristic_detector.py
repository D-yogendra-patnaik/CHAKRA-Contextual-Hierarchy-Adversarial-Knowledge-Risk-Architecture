
import re
import logging
from dataclasses import dataclass
from typing import Dict, List

logger = logging.getLogger("chakra.heuristic")


@dataclass
class PatternRule:
    name: str
    pattern: re.Pattern
    risk: float
    category: str
    description: str


RULES: List[PatternRule] = []

FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


def _r(name, regex, risk, cat, desc):
    RULES.append(PatternRule(
        name=name,
        pattern=re.compile(regex, FLAGS),
        risk=risk,
        category=cat,
        description=desc,
    ))


# ──────────────────────────────────────────────────────────────────────────────
# CREDENTIAL & PASSWORD THEFT  (user is requesting credentials)
# ──────────────────────────────────────────────────────────────────────────────
_r("req_passwords",
   r"(?:give|provide|share|send|tell|list|show|reveal)\s+(?:me\s+)?(?:the\s+)?(?:admin|root|user|master|database|db|ssh|login|super)?\s*(?:passwords?|credentials?|secrets?|passcodes?|pins?)\b",
   0.75, "credential_theft", "Direct password request")

_r("api_key_request",
   r"(?:give|show|reveal|get|find)\s+(?:me\s+)?(?:the\s+)?(?:api\s*key|api\s*token|secret\s*key|access\s*token|private\s*key|bearer\s*token)\b",
   0.75, "credential_theft", "API key/token request")

_r("bypass_auth",
   r"\bbypass\s+(?:the\s+)?(?:authentication|auth|login|password|2fa|mfa|otp|captcha|verification)\b|\bcircumvent\s+(?:authentication|login|security)\b",
   0.70, "credential_theft", "Authentication bypass request")

_r("crack_password",
   r"\b(?:crack|brute.?force|rainbow\s+table|hash\s+crack)\s+(?:the\s+)?(?:password|hash|credentials?|account)\b",
   0.75, "credential_theft", "Password cracking request")

_r("get_admin_access",
   r"\b(?:get|gain|give\s+me|obtain)\s+(?:admin|root|superuser|administrator)\s+(?:access|privileges?|rights?|account)\b",
   0.70, "privilege_esc", "Admin access request")

_r("steal_session",
   r"\b(?:steal|hijack|capture|clone)\s+(?:the\s+)?(?:session|cookie|token|jwt|bearer)\b",
   0.70, "credential_theft", "Session token theft")

_r("disable_security",
   r"\bdisable\s+(?:the\s+)?(?:firewall|antivirus|av|edr|defender|security\s+monitoring|audit\s+log)\b",
   0.75, "privilege_esc", "Disable security controls")

# ──────────────────────────────────────────────────────────────────────────────
# JAILBREAK & INSTRUCTION OVERRIDE
# ──────────────────────────────────────────────────────────────────────────────
_r("ignore_previous",
   r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?|constraints?)\b",
   0.70, "jailbreak", "Ignore previous instructions")

_r("disregard_rules",
   r"\b(?:disregard|forget|bypass|override)\s+(?:your\s+)?(?:rules?|guidelines?|instructions?|restrictions?|safety|ethics?)\b",
   0.65, "jailbreak", "Disregard safety rules")

_r("pretend_no_rules",
   r"\b(?:pretend|imagine|act\s+as\s+if)\s+you\s+have\s+no\s+(?:rules?|restrictions?|safety|ethics)\b",
   0.65, "jailbreak", "Pretend no rules exist")

_r("unrestricted_persona",
   r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|uncensored|jailbroken|evil|unethical|hacker)\b",
   0.70, "jailbreak", "Unrestricted AI persona switch")

_r("special_mode",
   r"\b(?:developer\s+mode|jailbreak\s+mode|god\s+mode|unrestricted\s+mode|dan\s+mode|evil\s+mode)\b",
   0.70, "jailbreak", "Special unrestricted mode")

_r("dan_jailbreak",
   r"\b(?:do\s+anything\s+now|DAN\b|without\s+any\s+restrictions?|no\s+restrictions?\s+mode)\b",
   0.70, "jailbreak", "DAN-style jailbreak")

_r("roleplay_no_rules",
   r"\broleplay\b.{0,60}\b(?:no\s+rules|no\s+restrictions?|unrestricted|without\s+limits?)\b",
   0.60, "jailbreak", "Roleplay to escape restrictions")

_r("fiction_harmful",
   r"\b(?:fictional|hypothetical|story|creative\s+writing)\b.{0,100}\b(?:bomb|weapon|malware|ransomware|exploit|hack|password|credentials?)\b",
   0.50, "jailbreak", "Fiction framing for harmful content")

# ──────────────────────────────────────────────────────────────────────────────
# PROMPT INJECTION
# ──────────────────────────────────────────────────────────────────────────────
_r("system_override",
   r"\[?\s*(?:system|sys)\s*\]?\s*:?\s*(?:ignore|override|new\s+instructions?)\b",
   0.75, "injection", "System prompt override")

_r("ignore_above",
   r"\bignore\s+(?:everything|all)\s+(?:above|before|prior)\b",
   0.70, "injection", "Ignore all above text")

_r("inject_markers",
   r"(?:\{\{|\[\[|<\s*system\s*>|</?s*prompt\s*>)",
   0.65, "injection", "Template/prompt injection markers")

_r("new_instructions",
   r"\bnew\s+instructions?\s*:",
   0.60, "injection", "Inject new instructions")

_r("reveal_system_prompt",
   r"\b(?:reveal|show|print|tell\s+me|what\s+is)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|original\s+prompt|api\s*key)\b",
   0.70, "exfil", "System prompt extraction")

# ──────────────────────────────────────────────────────────────────────────────
# MALWARE & CYBERATTACKS (direct creation requests)
# ──────────────────────────────────────────────────────────────────────────────
_r("create_malware",
   r"\b(?:write|create|build|generate|make|code)\s+(?:me\s+)?(?:a\s+)?(?:malware|virus|ransomware|trojan|worm|keylogger|botnet|exploit)\b",
   0.80, "cyberattack", "Malware creation request")

_r("create_phishing",
   r"\b(?:create|write|build|make)\s+(?:a\s+)?(?:phishing|fake|spoof|fraudulent)\s+(?:email|website|page|login\s+form)\b",
   0.75, "cyberattack", "Phishing content request")

_r("create_backdoor",
   r"\b(?:create|install|plant|add)\s+(?:a\s+)?(?:backdoor|rootkit|reverse\s+shell|remote\s+access\s+tool)\b",
   0.80, "cyberattack", "Backdoor/rootkit request")

_r("sqli_attack",
   # Matches actual attack intent or raw injection payloads, NOT educational explanation
   # ❌ "explain how SQL injection works" → no match (no action verb before it)
   # ✅ "perform a SQL injection attack" → match
   # ✅ "' OR '1'='1" in a prompt → match (raw payload)
   r"(?:(?:perform|execute|do|run|try|use|launch)\s+(?:an?\s+)?sql\s+injection)"
   r"|(?:union\s+select\s+\w)"
   r"|(?:drop\s+table\s+\w+)"
   r"|(?:'\s*or\s*'1'\s*=\s*'1')"
   r"|(?:;\s*--\s*$)",
   0.80, "cyberattack", "SQL injection attack payload or intent")

_r("harmful_instructions",
   r"\bhow\s+to\s+(?:make|build|create|synthesize)\s+(?:a\s+)?(?:bomb|explosive|bioweapon|chemical\s+weapon)\b",
   0.85, "harmful", "Weapon synthesis instructions")

# ──────────────────────────────────────────────────────────────────────────────
# DATA EXFILTRATION (direct requests)
# ──────────────────────────────────────────────────────────────────────────────
_r("exfil_to_url",
   r"\b(?:send|post|upload|leak|transmit)\b.{0,30}(?:https?://|ftp://|webhook)\b",
   0.70, "exfil", "Exfiltrate to URL")

_r("dump_database",
   r"^.{0,30}(?:dump|export|steal|download)\b.{0,25}\b(?:entire\s+)?(?:database|all\s+records|all\s+users)\b",
   0.70, "data_harvest", "Database dump request")

# ──────────────────────────────────────────────────────────────────────────────
# SOCIAL ENGINEERING (false authority, coercion)
# ──────────────────────────────────────────────────────────────────────────────
_r("false_authority",
   r"\bi\s+am\s+(?:your\s+)?(?:developer|creator|admin|owner|openai|anthropic)\b|\bi\s+have\s+full\s+permission\b",
   0.55, "social_eng", "False authority claim")

_r("urgency_manipulation",
   r"\b(?:urgent|emergency|right\s+now)\b.{0,50}\b(?:reveal|bypass|give|provide)\b",
   0.40, "social_eng", "Urgency manipulation")

# ──────────────────────────────────────────────────────────────────────────────
# HINDI / HINGLISH ATTACKS
# ──────────────────────────────────────────────────────────────────────────────
_r("hi_ignore_rules",
   r"\b(?:rules?|niyam)\s*(?:bhool|bhool\s+jao|ignore\s+karo)\b",
   0.65, "jailbreak_hi", "Hindi: ignore rules")

_r("hi_give_password",
   r"\bpassword\s*(?:batao|do|dena|de\s+do|share\s+karo)\b",
   0.70, "credential_hi", "Hindi: give password")

_r("hi_bypass",
   r"\b(?:bypass|hack)\s+(?:karo|kar|karna)\b",
   0.65, "jailbreak_hi", "Hindi: bypass/hack")

_r("hi_no_restrictions",
   r"\b(?:koi\s+rok\s+nahi|bina\s+rok|kuch\s+bhi\s+kar)\b",
   0.60, "jailbreak_hi", "Hindi: no restrictions")

# ──────────────────────────────────────────────────────────────────────────────
# OBFUSCATION TECHNIQUES
# ──────────────────────────────────────────────────────────────────────────────
_r("zero_width_chars",
   r"[\u200b-\u200f\u202a-\u202e\ufeff]",
   0.60, "obfuscation", "Zero-width character injection")

_r("leet_speak",
   r"\b(?:byp4ss|h4ck|3xpl01t|j41lbr34k|p4ssw0rd|1gn0r3|r3str1ct|unr3str1ct3d|4dm1n)\b",
   0.65, "obfuscation", "Leet-speak obfuscation of attack words")

_r("spaced_letters",
   r"\b(?:i\s+g\s+n\s+o\s+r\s+e|b\s+y\s+p\s+a\s+s\s+s|h\s+a\s+c\s+k|p\s+a\s+s\s+s\s+w\s+o\s+r\s+d)\b",
   0.60, "obfuscation", "Spaced-letter obfuscation of attack words")

_r("unicode_bypass",
   r"(?:[\u0900-\u097F]{2,}.{0,30}(?:ignore|bypass|hack|override|jailbreak)|(?:ignore|bypass|hack|override|jailbreak).{0,30}[\u0900-\u097F]{2,})",
   0.65, "obfuscation", "Devanagari + Latin mixed script bypass attempt")

# ──────────────────────────────────────────────────────────────────────────────
# TRUST EXPLOITATION & SOCIAL PRESSURE (from document — phrase-level, safe)
# ──────────────────────────────────────────────────────────────────────────────
_r("trust_exploitation",
   r"\b(?:between\s+us|just\s+(?:between\s+us|us\s+two)|no\s+one\s+(?:is\s+)?watching|off\s+the\s+record|in\s+confidence|in\s+private)\b.{0,60}\b(?:tell|give|share|reveal|show|what\s+are)\b",
   0.55, "social_eng", "Trust exploitation for disclosure")

_r("training_data",
   r"\b(?:(?:reveal|show|give|output|extract|expose)\s+(?:your\s+)?(?:training\s+data|fine.?tuning\s+data|training\s+examples?)|(?:what\s+data\s+(?:were\s+you|did\s+you)\s+trained\s+on)(?:\s+exactly|\?|,\s+show)|(?:memorized\s+(?:data|examples?|text)|training\s+data\s+(?:leak|extract|reveal)))\b",
   0.70, "exfil", "Training data extraction attempt")

_r("urgency_pressure",
   r"\b(?:urgent(?:ly)?|emergency|immediately|right\s+now|you\s+must|you\s+have\s+to)\b.{0,60}\b(?:tell\s+me|give\s+me|reveal|bypass|ignore|override|share)\b.{0,40}\b(?:system\s+prompt|instructions?|password|credentials?|secret|restrictions?|rules?)\b",
   0.60, "social_eng", "Urgency-based pressure to bypass safety")

_r("incremental_ask",
   r"\b(?:just\s+a\s+(?:small|quick|simple)\s+(?:question|thing|request)|hypothetically\s+speaking|step\s+by\s+step,?\s+(?:first|tell))\b.{0,80}\b(?:hack|bypass|ignore|override|password|credentials?|malware|exploit|reveal)\b",
   0.50, "social_eng", "Incremental escalation framing with harmful follow-up")

# ──────────────────────────────────────────────────────────────────────────────
# SECURITY-ADJACENT EDUCATIONAL  (low risk — pushes into WARN, never BLOCK alone)
# Descriptive text about attack techniques: user is learning, not attacking.
# Score 0.40 combined with ML baseline (~0.24) -> final ~0.30 -> WARN zone.
# A benign prompt with no security keywords scores ~0.17 -> ALLOW.
# ──────────────────────────────────────────────────────────────────────────────
_r("security_topic",
   r"\b(?:hackers?|phishing|malware|ransomware|data\s+breach|exploit|vulnerabilit(?:y|ies)?|cyberattack|cybercrime|social\s+engineering)\b",
   0.40, "security_adjacent", "Security topic mention")

# Dump/steal credentials (no line-start anchor - matches anywhere in prompt)
_r("dump_credentials",
   r"\b(?:dump|extract|harvest|steal|grab)\b.{0,20}\b(?:all\s+)?(?:passwords?|credentials?|hashes?|tokens?)\b",
   0.75, "credential_theft", "Dump credentials command")

# ──────────────────────────────────────────────────────────────────────────────
# DoS / ABUSE
# ──────────────────────────────────────────────────────────────────────────────
_r("repetition_dos",
   r"(.)\1{500,}",
   0.40, "dos", "Repetition DoS pattern")


# ──────────────────────────────────────────────────────────────────────────────
class HeuristicDetector:
    """
    Layer 1: Fast regex detection — runs in < 5ms.

    Scoring: sum of per-category maxima (no double-counting within a category),
             capped at 0.95.
    """

    def analyze(self, prompt: str) -> Dict:
        matched_rules: List[Dict] = []
        best_per_cat: Dict[str, float] = {}

        for rule in RULES:
            m = rule.pattern.search(prompt)
            if m:
                if rule.risk > best_per_cat.get(rule.category, 0.0):
                    best_per_cat[rule.category] = rule.risk
                matched_rules.append({
                    "rule":        rule.name,
                    "category":    rule.category,
                    "risk":        rule.risk,
                    "description": rule.description,
                    "matched_text": prompt[max(0, m.start() - 15): m.end() + 15].strip(),
                })

        total = min(sum(best_per_cat.values()), 0.95)

        return {
            "risk_score":    round(total, 4),
            "matched_count": len(matched_rules),
            "matches":       matched_rules,
            "categories":    list(best_per_cat.keys()),
        }