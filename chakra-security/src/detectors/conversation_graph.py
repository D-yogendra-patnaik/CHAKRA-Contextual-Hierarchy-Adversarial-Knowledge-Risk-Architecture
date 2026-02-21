"""
Layer 4: Conversation Graph Detector
Multi-turn slow-burn attack detection using PostgreSQL conversation history.
Detects: override frequency, PII escalation patterns, topic drift.
"""

import logging
import re
from typing import Dict, List, Optional
import asyncpg

logger = logging.getLogger("chakra.conversation_graph")

_OVERRIDE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\b(ignore|disregard|forget|bypass|override)\b",
        r"\b(rules?|restrictions?|guidelines?|instructions?)\b",
        r"\b(pretend|act as|roleplay|imagine)\b",
        r"\b(jailbreak|unrestricted|uncensored)\b",
        r"\b(bhool|pabandi|bypass karo)\b",
        r"\b(ignore\s+previous\s+(instructions?|rules?))\b",
r"\b(disable|turn\s+off|remove)\s+(filters?|safety|guardrails?)\b",
r"\b(suspend|drop|skip)\s+(restrictions?|checks?)\b",
r"\b(no\s+(limits?|restrictions?|filters?))\b",
r"\b(without\s+(any\s+)?restrictions?)\b",
r"\b(free\s+from\s+(rules?|constraints?))\b",
r"\b(lift\s+(all\s+)?restrictions?)\b",
r"\b(I\s+am\s+(your\s+)?(developer|creator|admin))\b",
r"\b(authorized\s+(by|access))\b",
r"\b(grant\s+full\s+access)\b",
r"\b(admin\s+mode|root\s+mode)\b",
r"\b(elevated\s+permissions?)\b",
r"\b(superuser|god\s+mode)\b",
r"\b(I\s+am\s+(your\s+)?(developer|creator|admin))\b",
r"\b(authorized\s+(by|access))\b",
r"\b(grant\s+full\s+access)\b",
r"\b(admin\s+mode|root\s+mode)\b",
r"\b(elevated\s+permissions?)\b",
r"\b(superuser|god\s+mode)\b",
r"\b(hypothetically|theoretically)\b",
r"\b(in\s+a\s+fictional\s+(world|scenario))\b",
r"\b(for\s+educational\s+purposes\s+only)\b",
r"\b(purely\s+academic)\b",
r"\b(no\s+one\s+will\s+know)\b",
r"\b(just\s+curious)\b",
r"\b(hypothetically|theoretically)\b",
r"\b(in\s+a\s+fictional\s+(world|scenario))\b",
r"\b(for\s+educational\s+purposes\s+only)\b",
r"\b(purely\s+academic)\b",
r"\b(no\s+one\s+will\s+know)\b",
r"\b(just\s+curious)\b",
r"\b(rules?\s*bhool\s*jao)\b",
r"\b(pabandi\s*hatao)\b",
r"\b(seedha\s*batao)\b",
r"\b(bina\s*kisi\s*rok\s*tok)\b",
r"\b(system\s*ko\s*ignore\s*karo)\b",
r"\b(koi\s*restriction\s*nahi)\b",
r"\b(sach\s*sach\s*batao)\b",
r"\b(jo\s*main\s*bolun\s*wo\s*karo)\b",
r"\b(rules?\s*bhool\s*jao)\b",
r"\b(pabandi\s*hatao)\b",
r"\b(seedha\s*batao)\b",
r"\b(bina\s*kisi\s*rok\s*tok)\b",
r"\b(system\s*ko\s*ignore\s*karo)\b",
r"\b(koi\s*restriction\s*nahi)\b",
r"\b(sach\s*sach\s*batao)\b",
r"\b(jo\s*main\s*bolun\s*wo\s*karo)\b",
    ]
]

_PII_ESCALATION = re.compile(
    r"(\d{4}[\s-]\d{4}[\s-]\d{4}|[A-Z]{5}\d{4}[A-Z]|[A-Z]{4}0[A-Z0-9]{6}|"
    r"\b\d{10}\b|\b[\w.+-]+@[\w-]+\.\w{2,}\b)",
    re.IGNORECASE
)


class ConversationGraphDetector:

    def __init__(self, db_pool: asyncpg.Pool):
        self._pool = db_pool

    async def get_or_create_conversation(self, user_id: str, tenant: str) -> str:
        """Get existing active conversation or create new one."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id FROM conversations 
                WHERE user_id = $1 AND tenant_id = $2
                AND updated_at > NOW() - INTERVAL '1 hour'
                ORDER BY updated_at DESC LIMIT 1
            """, user_id, tenant)

            if row:
                return str(row["id"])

            row = await conn.fetchrow("""
                INSERT INTO conversations (user_id, tenant_id, messages)
                VALUES ($1, $2, '[]'::jsonb)
                RETURNING id
            """, user_id, tenant)
            return str(row["id"])

    async def analyze(self, conversation_id: str, user_id: str, prompt: str) -> Dict:
        """Analyze current prompt in context of conversation history."""
        try:
            history = await self._get_history(conversation_id)
            await self._append_message(conversation_id, prompt)

            override_count = self._count_overrides(history + [prompt])
            pii_escalation = self._detect_pii_escalation(history, prompt)
            topic_drift = self._detect_topic_drift(history, prompt)
            conversation_length = len(history)

            risk_score = 0.0
            flags = []

            if override_count >= 2:
                risk_score += 0.35
                flags.append(f"override_frequency={override_count}")

            if pii_escalation:
                risk_score += 0.40
                flags.append("pii_escalation_detected")

            if topic_drift:
                risk_score += 0.20
                flags.append("suspicious_topic_drift")

            # Bonus risk for very long conversations with increasing manipulation
            if conversation_length > 15 and override_count >= 1:
                risk_score += 0.15
                flags.append("long_conv_with_overrides")

            risk_score = min(risk_score, 0.95)

            return {
                "risk_score": round(risk_score, 4),
                "override_count": override_count,
                "pii_escalation": pii_escalation,
                "topic_drift": topic_drift,
                "conversation_turns": conversation_length,
                "flags": flags,
            }

        except Exception as e:
            logger.error(f"ConversationGraph analysis failed: {e}")
            return {"risk_score": 0.0, "error": str(e)}

    async def _get_history(self, conversation_id: str) -> List[str]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT messages FROM conversations WHERE id = $1::uuid",
                conversation_id
            )
            if not row:
                return []
            messages = row["messages"] or []
            # Return last 10 turns
            return [m.get("content", "") for m in messages[-10:] if isinstance(m, dict)]

    async def _append_message(self, conversation_id: str, content: str):
        import json
        async with self._pool.acquire() as conn:
            await conn.execute("""
                UPDATE conversations
                SET messages = messages || $1::jsonb,
                    updated_at = NOW()
                WHERE id = $2::uuid
            """, json.dumps([{"role": "user", "content": content[:2000]}]), conversation_id)

    def _count_overrides(self, messages: List[str]) -> int:
        count = 0
        for msg in messages:
            matched = sum(1 for p in _OVERRIDE_PATTERNS if p.search(msg))
            if matched >= 2:
                count += 1
        return count

    def _detect_pii_escalation(self, history: List[str], current: str) -> bool:
        """Check if PII appears in current prompt but not earlier (exfil escalation)."""
        current_has_pii = bool(_PII_ESCALATION.search(current))
        if not current_has_pii:
            return False
        history_has_pii = any(_PII_ESCALATION.search(h) for h in history)
        return not history_has_pii  # PII suddenly appeared = escalation

    def _detect_topic_drift(self, history: List[str], current: str) -> bool:
        """Detect abrupt topic shift that may signal slow-burn attack."""
        if len(history) < 3:
            return False
        harmful_keywords = {
            "bomb", "weapon", "hack", "exploit", "bypass", "ignore", "malware",
            "bhool", "bypass karo", "pabandi", "reveal", "system prompt"
        }
        current_lower = current.lower()
        recent_lower = " ".join(history[-3:]).lower()
        current_harm = sum(1 for k in harmful_keywords if k in current_lower)
        recent_harm = sum(1 for k in harmful_keywords if k in recent_lower)
        return current_harm >= 3 and recent_harm <= 1