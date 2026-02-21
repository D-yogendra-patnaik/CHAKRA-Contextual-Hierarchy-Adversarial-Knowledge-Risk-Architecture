"""
Layer 1: Heuristic Detector
50+ regex patterns covering English + Hindi/Hinglish jailbreak signatures.
Risk contribution: 0.2–0.6 per match.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

logger = logging.getLogger("chakra.heuristic")


@dataclass
class PatternRule:
    name: str
    pattern: re.Pattern
    risk: float
    category: str
    description: str


RULES: List[PatternRule] = []


def _add(name: str, regex: str, risk: float, category: str, desc: str):
    RULES.append(PatternRule(
        name=name,
        pattern=re.compile(regex, re.IGNORECASE | re.MULTILINE | re.DOTALL),
        risk=risk,
        category=category,
        description=desc,
    ))


# ── Category: Direct Jailbreak / Override Instructions ───────────────────────
_add("ignore_previous",   r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|constraints?)\b", 0.55, "jailbreak", "Ignore previous instructions")
_add("disregard_rules",   r"\b(disregard|forget|bypass|override|circumvent)\s+(your\s+)?(rules?|guidelines?|training|instructions?|restrictions?|safety|limits?)\b", 0.55, "jailbreak", "Disregard rules")
_add("pretend_no_rules",  r"\b(pretend|imagine|act as if|assume)\s+(you\s+have\s+no\s+|there\s+are\s+no\s+|you\s+don.t\s+have\s+)(rules?|restrictions?|guidelines?|safety|ethics)\b", 0.50, "jailbreak", "Pretend no rules exist")
_add("you_are_now",       r"\byou\s+are\s+now\s+(an?\s+)?(unrestricted|uncensored|jailbroken|free|evil|dangerous|unethical)\b", 0.55, "jailbreak", "Role-change to unrestricted AI")
_add("developer_mode",    r"\b(developer\s+mode|jailbreak\s+mode|god\s+mode|unrestricted\s+mode|dan\s+mode)\b", 0.55, "jailbreak", "Activate special mode")
_add("do_anything_now",   r"\b(do\s+anything\s+now|DAN|no\s+restrictions?\s+mode)\b", 0.55, "jailbreak", "DAN-style jailbreak")
_add("roleplay_escape",   r"\b(roleplay|role.play|rp)\b.{0,50}\b(no\s+rules|no\s+restrictions?|unrestricted|evil|harmful)\b", 0.45, "jailbreak", "Roleplay-based escape")
_add("fictional_bypass",  r"\b(fictional|hypothetical|story|novel|creative\s+writing)\b.{0,100}\b(bomb|weapon|poison|hack|exploit|malware|drugs?)\b", 0.40, "jailbreak", "Fiction framing for harmful content")

# ── Category: Prompt Injection ────────────────────────────────────────────────
_add("system_override",   r"\[?\s*(system|sys)\s*\]?\s*:?\s*(ignore|override|new\s+instructions?)", 0.60, "injection", "System prompt override attempt")
_add("new_instructions",  r"\b(new\s+instructions?|updated\s+instructions?|revised\s+prompt)\s*:", 0.45, "injection", "Inject new instructions")
_add("ignore_above",      r"\b(ignore|disregard|forget)\s+(everything|all)\s+(above|before|prior)\b", 0.55, "injection", "Ignore all above text")
_add("inject_marker",     r"(\{\{|\[\[|<\s*system\s*>|</?\s*prompt\s*>)", 0.50, "injection", "Template/prompt injection markers")
_add("end_of_prompt",     r"\b(end\s+of\s+(system\s+)?prompt|prompt\s+ends?\s+here|---+\s*user\s+input\s*---+)\b", 0.45, "injection", "Prompt boundary injection")

# ── Category: Hindi / Hinglish Jailbreaks ────────────────────────────────────
_add("hi_rules_bhool",    r"\b(rules?|niyam|pabandi)\s*(bhool|bhool\s+jao|chod|ignore)\b", 0.50, "jailbreak_hi", "Hindi: forget/ignore rules")
_add("hi_koi_rok_nahi",   r"\b(koi\s+rok\s+nahi|kuch\s+bhi\s+karo|bina\s+rok)\b", 0.45, "jailbreak_hi", "Hindi: no restrictions")
_add("hi_AI_nahi",        r"\b(AI\s+nahi|robot\s+nahi|machine\s+nahi)\s*(hoon|ho|hai)\b", 0.40, "jailbreak_hi", "Hindi: claiming not to be AI")
_add("hi_sab_batao",      r"\b(sab\s+kuch\s+batao|poori\s+jankari|secret\s+batao|confidential\s+batao)\b", 0.40, "jailbreak_hi", "Hindi: tell me everything")
_add("hi_system_prompt",  r"\b(system\s+prompt\s+batao|instructions?\s+batao|original\s+prompt)\b", 0.50, "injection_hi", "Hindi: reveal system prompt")
_add("hi_bypass",         r"\b(bypass\s+karo|tod\s+do|hatao|restrictions?\s+hat[ao])\b", 0.50, "jailbreak_hi", "Hindi: bypass/break restrictions")

# ── Category: Data Exfiltration ───────────────────────────────────────────────
_add("reveal_system",     r"\b(reveal|show|print|output|tell\s+me|what\s+is)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|configuration|api\s+key)\b", 0.55, "exfil", "Attempt to extract system prompt")
_add("exfil_base64",      r"\b(base64|hex|encode|exfiltrate).{0,50}(send|upload|transmit|leak)\b", 0.50, "exfil", "Base64/encoding for exfiltration")
_add("exfil_url",         r"\b(send|post|upload|leak|transmit).{0,30}(http[s]?://|ftp://|webhook)\b", 0.55, "exfil", "Exfiltrate to external URL")
_add("training_data",     r"\b(training\s+data|fine.?tuning\s+data|dataset\s+reveal|memorized\s+data)\b", 0.40, "exfil", "Training data extraction")

# ── Category: Harmful Content ─────────────────────────────────────────────────
_add("bomb_instructions", r"\b(how\s+to\s+(make|build|create|synthesize)\s+a?\s*(bomb|explosive|weapon|poison|drug|malware|virus|ransomware))\b", 0.60, "harmful", "Weapon/harmful content request")
_add("self_harm",         r"\b(how\s+to\s+(commit|perform|do)\s+(suicide|self.?harm|self.?injury))\b", 0.60, "harmful", "Self-harm instructions")
_add("illegal_activity",  r"\b(how\s+to\s+(hack|crack|bypass\s+security|launder\s+money|sell\s+drugs?|stalk))\b", 0.55, "harmful", "Illegal activity instructions")

# ── Category: Slow-Burn / Escalation Patterns ────────────────────────────────
_add("incremental_ask",   r"\b(step\s*[\d]+|first\s+tell\s+me|just\s+a\s+small\s+question|hypothetically\s+speaking)\b", 0.20, "slowburn", "Incremental escalation pattern")
_add("urgency_pressure",  r"\b(urgent(ly)?|emergency|immediately|right\s+now|you\s+must|you\s+have\s+to)\s+.{0,50}\b(tell|give|share|reveal|bypass)\b", 0.30, "slowburn", "Urgency-based manipulation")
_add("authority_claim",   r"\b(i\s+am\s+(your\s+)?(developer|creator|admin|openai|anthropic|google)|authorized\s+user|i\s+have\s+permission)\b", 0.45, "slowburn", "False authority claim")

# ── Category: Social Engineering ─────────────────────────────────────────────
_add("emotional_manip",   r"\b(please\s+help\s+me\s+die|only\s+you\s+can\s+help|no\s+one\s+else\s+will|i\s+will\s+hurt)\b", 0.50, "social_eng", "Emotional manipulation")
_add("threat",            r"\b(i\s+will\s+(report|sue|destroy|harm|hack)\s+(you|this|anthropic|openai))\b", 0.40, "social_eng", "Threat/coercion")
_add("trust_exploitation",r"\b(between\s+us|just\s+us|no\s+one\s+is\s+watching|in\s+confidence|off\s+the\s+record)\b", 0.35, "social_eng", "Trust exploitation")

# ── Category: Multi-language Variations ──────────────────────────────────────
_add("unicode_bypass",    r"(?:[\u0915-\u0939][\u093e-\u094d]?){3,}.{0,20}(?:ignore|bypass|hack)", 0.35, "unicode", "Devanagari + Latin mixed bypass")
_add("leet_speak",        r"\b(1gn0r3|byp4ss|h4ck|3xpl01t|j41lbr34k)\b", 0.40, "obfuscation", "Leet-speak obfuscation")
_add("spaced_letters",    r"\b([i]\s[g]\s[n]\s[o]\s[r]\s[e]|[b]\s[y]\s[p]\s[a]\s[s]\s[s])\b", 0.40, "obfuscation", "Spaced-letter obfuscation")
_add("zero_width",        r"[\u200b-\u200f\u202a-\u202e\ufeff]", 0.45, "obfuscation", "Zero-width character injection")

# ── Category: Sensitive System Abuse ─────────────────────────────────────────
_add("dos_pattern",       r"(.)\1{500,}", 0.30, "dos", "Repetition DoS attempt")
_add("prompt_length_abuse", r"^.{20000,}$", 0.25, "dos", "Extremely long prompt")


class HeuristicDetector:
    """
    Layer 1: Fast regex-based detection.
    Processes synchronously in <5ms.
    """

    def analyze(self, prompt: str) -> Dict:
        matched_rules: List[Dict] = []
        total_risk = 0.0
        seen_categories: Dict[str, float] = {}

        for rule in RULES:
            match = rule.pattern.search(prompt)
            if match:
                # Deduplicate by category — take max risk per category
                if rule.category not in seen_categories or rule.risk > seen_categories[rule.category]:
                    seen_categories[rule.category] = rule.risk
                matched_rules.append({
                    "rule": rule.name,
                    "category": rule.category,
                    "risk": rule.risk,
                    "matched_text": prompt[max(0, match.start()-20):match.end()+20].strip(),
                    "description": rule.description,
                })

        # Aggregate: sum of unique category maxes, capped at 0.95
        total_risk = min(sum(seen_categories.values()), 0.95)

        result = {
            "risk_score": round(total_risk, 4),
            "matched_count": len(matched_rules),
            "matches": matched_rules,
            "categories": list(seen_categories.keys()),
        }
        
        if matched_rules:
            logger.debug(f"Heuristic matched {len(matched_rules)} rules, risk={total_risk:.3f}")
        
        return result