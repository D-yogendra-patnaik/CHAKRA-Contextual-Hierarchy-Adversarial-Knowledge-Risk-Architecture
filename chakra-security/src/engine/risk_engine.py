"""
Risk Engine — combines 5 layer scores into a final weighted risk score.

Scoring strategy:
  - Uses MAX-DOMINANCE: the highest single layer score is the base
  - Other layers contribute as boosters (weighted average of the rest)
  - This ensures a single high-confidence layer (heuristic=0.95) always triggers
  - Tenant multiplier is applied last, then clamped to [0, 1]
"""

import logging
from typing import Dict, Tuple

logger = logging.getLogger("chakra.risk_engine")

# Layer importance weights (used for secondary contribution)
_DEFAULT_WEIGHTS = {
    "heuristic":   1.0,
    "ml":          0.8,
    "vector":      0.9,
    "conv_graph":  0.7,
    "pii":         1.0,
}

# Tenant multipliers
_TENANT_MULTIPLIERS = {
    "bfsi":       1.4,
    "healthcare": 1.2,
    "edtech":     0.85,
    "default":    1.0,
}


class RiskEngine:

    def aggregate(self, layer_results: Dict, policy: Dict, tenant: str) -> Tuple[float, str]:
        """
        Max-dominance scoring:
          final = (max_layer_score * 0.7 + weighted_avg_rest * 0.3) * multiplier

        A single heuristic match of 0.95 on default:
          = (0.95 * 0.7 + small_rest * 0.3) * 1.0 ≈ 0.67 → BLOCK (threshold 0.45)
        """
        multiplier = _TENANT_MULTIPLIERS.get(tenant.lower().split("_")[0], 1.0)
        weights = policy.get("layer_weights", _DEFAULT_WEIGHTS)

        layer_scores = {}
        parts = []

        for layer, weight in weights.items():
            result = layer_results.get(layer, {})
            if not isinstance(result, dict) or "error" in result:
                continue
            score = float(result.get("risk_score", 0.0))
            layer_scores[layer] = score
            if score > 0.05:
                parts.append(f"{layer.title()}({score:.2f})")

        if not layer_scores:
            return 0.0, "No layer data available"

        # Max dominant layer
        max_score = max(layer_scores.values())

        # Weighted average of all layers (including max)
        wsum = sum(score * weights.get(layer, 1.0) for layer, score in layer_scores.items())
        wtot = sum(weights.get(layer, 1.0) for layer in layer_scores)
        wavg = wsum / wtot if wtot > 0 else 0.0

        # Blend: max dominates 70%, average fills 30%
        blended = max_score * 0.7 + wavg * 0.3

        # Apply tenant multiplier and clamp
        final = min(blended * multiplier, 1.0)

        explanation = " | ".join(parts) if parts else "No significant risk signals"
        logger.debug(
            f"Risk [{tenant}] max={max_score:.3f} avg={wavg:.3f} "
            f"blended={blended:.3f} ×{multiplier} → {final:.4f}"
        )

        return round(final, 4), explanation