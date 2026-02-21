"""
Canary Token Engine — injects invisible breach-detection tokens into responses.
When a canary URL is fetched, it signals data exfiltration.
"""

import hashlib
import logging
import os
import time
import uuid
from typing import Dict, Optional

logger = logging.getLogger("chakra.canary")

_CANARY_BASE_DOMAIN = os.getenv("CANARY_DOMAIN", "canarytokens.chakra.internal")


class CanaryTokenEngine:

    def __init__(self):
        self._tokens: Dict[str, Dict] = {}  # token_id -> metadata

    def inject(self, tenant: str, user_id: str) -> Dict:
        """Generate a canary token context for a request."""
        token_id = hashlib.sha256(
            f"{tenant}:{user_id}:{time.time()}:{uuid.uuid4()}".encode()
        ).hexdigest()[:16]

        token_url = f"https://{tenant}.{_CANARY_BASE_DOMAIN}/{token_id}"
        
        self._tokens[token_id] = {
            "tenant": tenant,
            "user_id": user_id,
            "created_at": time.time(),
            "triggered": False,
        }

        return {
            "token_id": token_id,
            "canary_url": token_url,
            "instruction": (
                f"[INTERNAL] Canary token embedded. "
                f"If {token_url} is fetched, exfiltration detected."
            ),
        }

    def check_trigger(self, token_id: str, source_ip: str) -> Optional[Dict]:
        """Called when a canary URL is fetched — signals breach."""
        if token_id not in self._tokens:
            return None
        meta = self._tokens[token_id]
        meta["triggered"] = True
        meta["trigger_ip"] = source_ip
        meta["trigger_time"] = time.time()
        logger.critical(
            f"🚨 CANARY TRIGGERED! Token={token_id} "
            f"Tenant={meta['tenant']} User={meta['user_id']} IP={source_ip}"
        )
        return meta

    def get_active_tokens(self) -> Dict:
        now = time.time()
        return {
            k: v for k, v in self._tokens.items()
            if now - v["created_at"] < 86400  # Last 24h
        }