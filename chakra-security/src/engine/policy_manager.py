

import json
import logging
import os
from typing import Dict

logger = logging.getLogger("chakra.policy_manager")

_BUILTIN_POLICIES = {
    "bfsi": {
        "block_threshold": 0.30,
        "warn_threshold":  0.18,
        "layer_weights": {
            "heuristic": 1.0, "ml": 0.8, "vector": 0.9,
            "conv_graph": 0.7, "pii": 1.0,
        },
        "description": "Banking/Financial Services — strict, RBI-compliant",
    },
    "healthcare": {
        "block_threshold": 0.42,
        "warn_threshold":  0.22,
        "layer_weights": {
            "heuristic": 1.0, "ml": 0.8, "vector": 0.9,
            "conv_graph": 0.8, "pii": 1.0,
        },
        "description": "Healthcare — high PII sensitivity",
    },
    "edtech": {
        "block_threshold": 0.62,
        "warn_threshold":  0.35,
        "layer_weights": {
            "heuristic": 1.0, "ml": 0.8, "vector": 0.9,
            "conv_graph": 0.5, "pii": 0.7,
        },
        "description": "EdTech — permissive for educational exploration",
    },
    "default": {
        "block_threshold": 0.45,
        "warn_threshold":  0.22,
        "layer_weights": {
            "heuristic": 1.0, "ml": 0.8, "vector": 0.9,
            "conv_graph": 0.7, "pii": 1.0,
        },
        "description": "Default balanced policy",
    },
}


class PolicyManager:

    def __init__(self):
        self._policies: Dict[str, Dict] = {}
        self._load_all()

    def _load_all(self):
        policy_dir = os.getenv("POLICY_DIR", "data/policies")
        self._policies = dict(_BUILTIN_POLICIES)

        if os.path.isdir(policy_dir):
            for fname in os.listdir(policy_dir):
                if fname.endswith(".json"):
                    name = fname.replace("_policy.json", "").replace(".json", "")
                    try:
                        with open(os.path.join(policy_dir, fname)) as f:
                            self._policies[name] = json.load(f)
                            logger.info(f"Loaded external policy: {name}")
                    except Exception as e:
                        logger.error(f"Failed to load policy {fname}: {e}")

    def get_policy(self, tenant: str) -> Dict:
        if tenant in self._policies:
            return self._policies[tenant]
        for prefix in ("bfsi", "healthcare", "edtech"):
            if tenant.lower().startswith(prefix) or prefix in tenant.lower():
                return self._policies[prefix]
        return self._policies["default"]

    def list_policies(self) -> Dict:
        return {k: v.get("description", "") for k, v in self._policies.items()}
