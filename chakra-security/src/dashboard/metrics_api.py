"""
Metrics API — Prometheus-compatible metrics + in-memory stats.
"""

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Dict


class MetricsCollector:

    def __init__(self):
        self._lock = Lock()
        self._blocks: Dict[str, int] = defaultdict(int)
        self._warns: Dict[str, int] = defaultdict(int)
        self._allows: Dict[str, int] = defaultdict(int)
        self._rate_limits: Dict[str, int] = defaultdict(int)
        self._latencies: deque = deque(maxlen=1000)  # rolling window
        self._start_time = time.time()

    def record_detection(self, tenant: str, risk_score: float, latency_ms: float):
        with self._lock:
            self._latencies.append(latency_ms)
            if risk_score < 0.2:
                self._allows[tenant] += 1

    def record_block(self, tenant: str):
        with self._lock:
            self._blocks[tenant] += 1

    def record_warn(self, tenant: str):
        with self._lock:
            self._warns[tenant] += 1

    def record_rate_limit(self, ip: str):
        with self._lock:
            self._rate_limits[ip] += 1

    def get_stats(self) -> Dict:
        with self._lock:
            lats = list(self._latencies)
            avg_latency = sum(lats) / len(lats) if lats else 0
            return {
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "blocks_by_tenant": dict(self._blocks),
                "warns_by_tenant": dict(self._warns),
                "allows_by_tenant": dict(self._allows),
                "total_blocks": sum(self._blocks.values()),
                "total_warns": sum(self._warns.values()),
                "total_allows": sum(self._allows.values()),
                "avg_latency_ms": round(avg_latency, 2),
                "p95_latency_ms": round(sorted(lats)[int(len(lats) * 0.95)] if lats else 0, 2),
                "rate_limit_hits": sum(self._rate_limits.values()),
            }


def generate_prometheus_output(metrics: MetricsCollector) -> str:
    stats = metrics.get_stats()
    lines = [
        "# HELP chakra_blocks_total Total prompts blocked",
        "# TYPE chakra_blocks_total counter",
        f"chakra_blocks_total {stats['total_blocks']}",
        "",
        "# HELP chakra_warns_total Total prompts warned",
        "# TYPE chakra_warns_total counter",
        f"chakra_warns_total {stats['total_warns']}",
        "",
        "# HELP chakra_latency_ms_avg Average detection latency in ms",
        "# TYPE chakra_latency_ms_avg gauge",
        f"chakra_latency_ms_avg {stats['avg_latency_ms']}",
        "",
        "# HELP chakra_latency_ms_p95 P95 detection latency in ms",
        "# TYPE chakra_latency_ms_p95 gauge",
        f"chakra_latency_ms_p95 {stats['p95_latency_ms']}",
        "",
        "# HELP chakra_uptime_seconds Gateway uptime in seconds",
        "# TYPE chakra_uptime_seconds gauge",
        f"chakra_uptime_seconds {stats['uptime_seconds']}",
    ]
    # Per-tenant breakdowns
    for tenant, count in stats["blocks_by_tenant"].items():
        lines.append(f'chakra_blocks_total{{tenant="{tenant}"}} {count}')
    return "\n".join(lines) + "\n"