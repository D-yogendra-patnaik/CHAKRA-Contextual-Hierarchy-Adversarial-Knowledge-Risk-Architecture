
import hashlib
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# Time-series bucket — stores (timestamp, value) pairs for sliding windows
# ══════════════════════════════════════════════════════════════════════════════

class TimeSeries:
    """
    Rolling time-series with configurable bucket width and retention.
    Automatically evicts data older than `retain_seconds`.
    """

    def __init__(self, bucket_seconds: int = 60, retain_seconds: int = 3600):
        self._bucket  = bucket_seconds
        self._retain  = retain_seconds
        self._data: deque = deque()  # [(bucket_ts, value), ...]
        self._lock = Lock()

    def record(self, value: float = 1.0):
        now = time.time()
        bucket_ts = int(now // self._bucket) * self._bucket
        with self._lock:
            self._evict(now)
            # Accumulate into current bucket
            if self._data and self._data[-1][0] == bucket_ts:
                last_ts, last_val = self._data[-1]
                self._data[-1] = (last_ts, last_val + value)
            else:
                self._data.append((bucket_ts, value))

    def _evict(self, now: float):
        cutoff = now - self._retain
        while self._data and self._data[0][0] < cutoff:
            self._data.popleft()

    def get_buckets(self, last_seconds: int = 300) -> List[Tuple[int, float]]:
        now = time.time()
        cutoff = now - last_seconds
        with self._lock:
            self._evict(now)
            return [(ts, val) for ts, val in self._data if ts >= cutoff]

    def rate_per_minute(self, window_seconds: int = 60) -> float:
        buckets = self.get_buckets(window_seconds)
        total = sum(v for _, v in buckets)
        return round(total / (window_seconds / 60), 2)

    def total(self) -> float:
        with self._lock:
            return sum(v for _, v in self._data)


# ══════════════════════════════════════════════════════════════════════════════
# Latency tracker — online percentile calculation
# ══════════════════════════════════════════════════════════════════════════════

class LatencyTracker:
    """
    Maintains a rolling window of latency samples.
    Computes P50/P75/P95/P99 without storing full sorted history.
    """

    def __init__(self, maxlen: int = 2000):
        self._samples: deque = deque(maxlen=maxlen)
        self._lock = Lock()

    def record(self, latency_ms: float):
        with self._lock:
            self._samples.append(latency_ms)

    def percentile(self, p: float) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            s = sorted(self._samples)
            idx = max(0, int(len(s) * p / 100) - 1)
            return round(s[idx], 2)

    def stats(self) -> Dict[str, float]:
        with self._lock:
            if not self._samples:
                return {k: 0.0 for k in ("avg","p50","p75","p95","p99","min","max")}
            s = sorted(self._samples)
            n = len(s)
            return {
                "avg": round(sum(s) / n, 2),
                "p50": round(s[int(n * 0.50)], 2),
                "p75": round(s[int(n * 0.75)], 2),
                "p95": round(s[int(n * 0.95)], 2),
                "p99": round(s[min(int(n * 0.99), n-1)], 2),
                "min": round(s[0], 2),
                "max": round(s[-1], 2),
            }


# ══════════════════════════════════════════════════════════════════════════════
# Histogram — tracks distribution of a value (e.g. risk scores)
# ══════════════════════════════════════════════════════════════════════════════

class Histogram:
    """
    Fixed-bucket histogram.
    Default buckets split [0,1] into 10 equal bands for risk scores.
    """

    def __init__(self, buckets: Optional[List[float]] = None):
        self._buckets = buckets or [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        self._counts = [0] * len(self._buckets)
        self._lock = Lock()

    def record(self, value: float):
        with self._lock:
            for i, bound in enumerate(self._buckets):
                if value <= bound:
                    self._counts[i] += 1
                    return
            self._counts[-1] += 1  # overflow

    def get(self) -> Dict[str, int]:
        with self._lock:
            prev = 0.0
            result = {}
            for bound, count in zip(self._buckets, self._counts):
                result[f"{prev:.1f}-{bound:.1f}"] = count
                prev = bound
            return result


# ══════════════════════════════════════════════════════════════════════════════
# Main Collector
# ══════════════════════════════════════════════════════════════════════════════

class MetricsCollector:
    """
    Central telemetry hub for the Chakra LLM Security Gateway.

    Thread-safe. All public methods are safe to call from async contexts
    (they release the GIL quickly via short critical sections).
    """

    def __init__(self):
        self._start_time = time.time()
        self._lock = Lock()

        # ── Counters by tenant ──────────────────────────────────────────────
        self._blocks:       Dict[str, int] = defaultdict(int)
        self._warns:        Dict[str, int] = defaultdict(int)
        self._allows:       Dict[str, int] = defaultdict(int)
        self._rate_limits:  Dict[str, int] = defaultdict(int)

        # ── LLM-specific counters ───────────────────────────────────────────
        self._total_prompts:        int = 0
        self._total_prompt_chars:   int = 0  # proxy for token count
        self._model_usage:          Dict[str, int] = defaultdict(int)
        self._tenant_request_count: Dict[str, int] = defaultdict(int)

        # ── Per-layer contribution tracking ────────────────────────────────
        # How often each layer was the *dominant* (highest-scoring) layer
        self._layer_dominant_count: Dict[str, int] = defaultdict(int)
        # Cumulative score sum per layer (for avg contribution)
        self._layer_score_sum:      Dict[str, float] = defaultdict(float)
        self._layer_score_count:    Dict[str, int]   = defaultdict(int)

        # ── Threat category tracking ────────────────────────────────────────
        self._threat_categories:   Dict[str, int] = defaultdict(int)
        self._threat_by_tenant:    Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # ── Jailbreak fingerprinting (deduplicated by prompt hash) ──────────
        self._jailbreak_hashes: set = set()       # unique attack fingerprints
        self._jailbreak_total:  int = 0           # includes repeats

        # ── False-positive estimation ───────────────────────────────────────
        # WARN prompts that were later manually marked as benign
        self._false_positive_count: int = 0
        # Track ALLOW counts right after WARN to detect threshold issues
        self._post_warn_allows:     deque = deque(maxlen=100)

        # ── Latency trackers ────────────────────────────────────────────────
        self._latency = LatencyTracker(maxlen=2000)
        self._latency_by_tenant: Dict[str, LatencyTracker] = {}

        # ── Sliding-window time series (for sparklines + rate calc) ─────────
        self._ts_requests = TimeSeries(bucket_seconds=60)
        self._ts_blocks   = TimeSeries(bucket_seconds=60)
        self._ts_warns    = TimeSeries(bucket_seconds=60)
        self._ts_allows   = TimeSeries(bucket_seconds=60)

        # ── Risk score distribution ─────────────────────────────────────────
        self._risk_histogram = Histogram()
        self._risk_histogram_by_tenant: Dict[str, Histogram] = {}

        # ── Prompt length distribution (chars) ─────────────────────────────
        _len_buckets = [50, 100, 200, 500, 1000, 2000, 5000, 10000, 50000]
        self._prompt_len_histogram = Histogram(buckets=[float(b) for b in _len_buckets])

        # ── Rolling 60-min risk scores for trend line ───────────────────────
        self._recent_risk_scores: deque = deque(maxlen=500)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _get_latency_tracker(self, tenant: str) -> LatencyTracker:
        if tenant not in self._latency_by_tenant:
            self._latency_by_tenant[tenant] = LatencyTracker(maxlen=500)
        return self._latency_by_tenant[tenant]

    def _get_risk_histogram(self, tenant: str) -> Histogram:
        if tenant not in self._risk_histogram_by_tenant:
            self._risk_histogram_by_tenant[tenant] = Histogram()
        return self._risk_histogram_by_tenant[tenant]

    # ══════════════════════════════════════════════════════════════════════
    # PUBLIC RECORDING METHODS
    # ══════════════════════════════════════════════════════════════════════

    def record_detection(
        self,
        tenant: str,
        risk_score: float,
        latency_ms: float,
        layer_breakdown: Optional[Dict[str, Any]] = None,
        prompt: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Called after every detection pipeline run regardless of action.
        Records latency, risk score, layer contributions, prompt stats.
        """
        # Time-series
        self._ts_requests.record()

        # Latency
        self._latency.record(latency_ms)
        self._get_latency_tracker(tenant).record(latency_ms)

        # Risk score histogram
        self._risk_histogram.record(risk_score)
        self._get_risk_histogram(tenant).record(risk_score)

        with self._lock:
            self._recent_risk_scores.append((time.time(), risk_score))
            self._tenant_request_count[tenant] += 1
            self._total_prompts += 1

            # Prompt length
            if prompt:
                self._total_prompt_chars += len(prompt)
                self._prompt_len_histogram.record(float(len(prompt)))

            # Model tracking
            if model:
                self._model_usage[model] += 1

            # Layer breakdown analysis
            if layer_breakdown:
                self._record_layer_stats(layer_breakdown)

    def _record_layer_stats(self, lb: Dict[str, Any]):
        """Determine dominant layer and record per-layer score sums."""
        layers = ["heuristic", "ml", "vector", "conv_graph", "pii"]
        best_layer = None
        best_score = -1.0
        for layer in layers:
            result = lb.get(layer, {})
            if not isinstance(result, dict):
                continue
            score = float(result.get("risk_score", 0.0))
            self._layer_score_sum[layer]   += score
            self._layer_score_count[layer] += 1
            if score > best_score:
                best_score  = score
                best_layer  = layer

        # Track which categories fired
        matches = lb.get("heuristic", {}).get("matches", [])
        for m in matches:
            cat = m.get("category", "unknown")
            self._threat_categories[cat] += 1

        if lb.get("pii", {}).get("risk_score", 0) > 0.3:
            self._threat_categories["pii"] += 1

        if best_layer and best_score > 0.2:
            self._layer_dominant_count[best_layer] += 1

    def record_block(self, tenant: str, prompt: Optional[str] = None):
        self._ts_blocks.record()
        with self._lock:
            self._blocks[tenant] += 1
            self._jailbreak_total += 1
            if prompt:
                h = hashlib.md5(prompt.strip().lower().encode()).hexdigest()[:12]
                self._jailbreak_hashes.add(h)

    def record_warn(self, tenant: str):
        self._ts_warns.record()
        with self._lock:
            self._warns[tenant] += 1

    def record_allow(self, tenant: str):
        """Call this explicitly to track ALLOW separately from record_detection."""
        self._ts_allows.record()
        with self._lock:
            self._allows[tenant] += 1

    def record_rate_limit(self, ip: str):
        with self._lock:
            self._rate_limits[ip] += 1

    def record_false_positive(self):
        """Call when a human reviewer marks a WARN/BLOCK as incorrect."""
        with self._lock:
            self._false_positive_count += 1

    def record_threat_categories(self, categories: List[str], tenant: str):
        """Record threat categories from heuristic matches."""
        with self._lock:
            for cat in categories:
                self._threat_categories[cat] += 1
                self._threat_by_tenant[tenant][cat] += 1

    # ══════════════════════════════════════════════════════════════════════
    # STATS RETRIEVAL
    # ══════════════════════════════════════════════════════════════════════

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns full stats dict — used by /v1/dashboard/stats endpoint
        and consumed by the realtime dashboard.
        """
        with self._lock:
            total_b = sum(self._blocks.values())
            total_w = sum(self._warns.values())
            total_a = sum(self._allows.values())
            # Only count actual user requests, not the stats API calls themselves
            total   = self._total_prompts

            # Layer average contributions
            layer_avg = {}
            for layer in ["heuristic", "ml", "vector", "conv_graph", "pii"]:
                cnt = self._layer_score_count.get(layer, 0)
                s   = self._layer_score_sum.get(layer, 0.0)
                layer_avg[layer] = round(s / cnt, 4) if cnt else 0.0

            # Layer dominance %
            total_dom = sum(self._layer_dominant_count.values()) or 1
            layer_dominance = {
                l: round(100 * c / total_dom, 1)
                for l, c in self._layer_dominant_count.items()
            }

            # Recent risk trend (last 20 scores)
            recent = list(self._recent_risk_scores)[-20:]
            risk_trend = [round(s, 4) for _, s in recent]

            # Unique vs repeated attack fingerprints
            unique_attacks   = len(self._jailbreak_hashes)
            repeated_attacks = max(0, self._jailbreak_total - unique_attacks)

            # Threat rate (requests per minute, last 5 min)
            block_rate = self._ts_blocks.rate_per_minute(300)
            req_rate   = self._ts_requests.rate_per_minute(300)

        lat_stats = self._latency.stats()

        return {
            # ── Core counters ─────────────────────────────────────
            "uptime_seconds":      round(time.time() - self._start_time, 1),
            "total_requests":      total,
            "total_blocks":        total_b,
            "total_warns":         total_w,
            "total_allows":        total_a,

            # ── Rates ─────────────────────────────────────────────
            "requests_per_minute": req_rate,
            "blocks_per_minute":   block_rate,
            "block_rate_pct":      round(100 * total_b / total, 2) if total > 0 else 0.0,
            "warn_rate_pct":       round(100 * total_w / total, 2) if total > 0 else 0.0,
            "allow_rate_pct":      round(100 * total_a / total, 2) if total > 0 else 0.0,

            # ── Latency ───────────────────────────────────────────
            "avg_latency_ms":  lat_stats["avg"],
            "p50_latency_ms":  lat_stats["p50"],
            "p75_latency_ms":  lat_stats["p75"],
            "p95_latency_ms":  lat_stats["p95"],
            "p99_latency_ms":  lat_stats["p99"],
            "min_latency_ms":  lat_stats["min"],
            "max_latency_ms":  lat_stats["max"],

            # ── Per-tenant breakdowns ──────────────────────────────
            "blocks_by_tenant":   dict(self._blocks),
            "warns_by_tenant":    dict(self._warns),
            "allows_by_tenant":   dict(self._allows),
            "requests_by_tenant": dict(self._tenant_request_count),

            # ── LLM-specific ───────────────────────────────────────
            "total_prompt_chars":       self._total_prompt_chars,
            "avg_prompt_chars":         round(self._total_prompt_chars / total, 1) if total > 0 else 0.0,
            "model_usage":              dict(self._model_usage),
            "prompt_length_histogram":  self._prompt_len_histogram.get(),

            # ── Layer intelligence ─────────────────────────────────
            "layer_avg_contribution":  layer_avg,
            "layer_dominance_pct":     layer_dominance,

            # ── Threat intelligence ────────────────────────────────
            "threat_categories":    dict(self._threat_categories),
            "threat_by_tenant":     {t: dict(c) for t, c in self._threat_by_tenant.items()},
            "top_threat_category":  max(self._threat_categories, key=self._threat_categories.get, default="none"),
            "unique_attack_fingerprints": unique_attacks,
            "repeated_attack_attempts":   repeated_attacks,

            # ── Risk distribution ──────────────────────────────────
            "risk_score_histogram":         self._risk_histogram.get(),
            "risk_trend_last20":            risk_trend,

            # ── Reliability signals ────────────────────────────────
            "false_positive_count":  self._false_positive_count,
            "rate_limit_hits":       sum(self._rate_limits.values()),

            # ── Time series (for sparklines, last 5 min, 1-min buckets) ──
            "timeseries": {
                "requests": self._ts_requests.get_buckets(300),
                "blocks":   self._ts_blocks.get_buckets(300),
                "warns":    self._ts_warns.get_buckets(300),
            },
        }

    def get_tenant_stats(self, tenant: str) -> Dict[str, Any]:
        """Per-tenant deep stats for tenant-specific dashboards."""
        lat = self._get_latency_tracker(tenant).stats()
        hist = self._get_risk_histogram(tenant).get()
        with self._lock:
            return {
                "tenant":             tenant,
                "total_requests":     self._tenant_request_count.get(tenant, 0),
                "blocks":             self._blocks.get(tenant, 0),
                "warns":              self._warns.get(tenant, 0),
                "allows":             self._allows.get(tenant, 0),
                "latency":            lat,
                "risk_histogram":     hist,
                "threat_categories":  dict(self._threat_by_tenant.get(tenant, {})),
            }


# ══════════════════════════════════════════════════════════════════════════════
# Prometheus output
# ══════════════════════════════════════════════════════════════════════════════

def generate_prometheus_output(metrics: MetricsCollector) -> str:
    s = metrics.get_stats()
    lines = []

    def metric(name, help_text, mtype, value, labels: Optional[Dict] = None):
        lstr = ""
        if labels:
            lstr = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"
        lines.extend([
            f"# HELP {name} {help_text}",
            f"# TYPE {name} {mtype}",
            f"{name}{lstr} {value}",
            "",
        ])

    # ── Core ──────────────────────────────────────────────────────────────
    metric("chakra_requests_total",     "Total prompts analyzed",      "counter", s["total_requests"])
    metric("chakra_blocks_total",       "Total prompts blocked",        "counter", s["total_blocks"])
    metric("chakra_warns_total",        "Total prompts warned",         "counter", s["total_warns"])
    metric("chakra_allows_total",       "Total prompts allowed",        "counter", s["total_allows"])
    metric("chakra_block_rate_pct",     "Block rate percentage",        "gauge",   s["block_rate_pct"])
    metric("chakra_uptime_seconds",     "Gateway uptime in seconds",    "gauge",   s["uptime_seconds"])

    # ── Rates ─────────────────────────────────────────────────────────────
    metric("chakra_requests_per_minute", "Requests per minute (5-min window)", "gauge", s["requests_per_minute"])
    metric("chakra_blocks_per_minute",   "Blocks per minute (5-min window)",   "gauge", s["blocks_per_minute"])
    metric("chakra_rate_limit_hits",     "Total rate limit hits",              "counter", s["rate_limit_hits"])

    # ── Latency ───────────────────────────────────────────────────────────
    for pct in ("avg", "p50", "p75", "p95", "p99"):
        metric(
            f"chakra_latency_ms_{pct}",
            f"Detection latency {pct} in milliseconds",
            "gauge",
            s[f"{pct}_latency_ms"],
        )

    # ── LLM-specific ──────────────────────────────────────────────────────
    metric("chakra_total_prompt_chars", "Total characters processed",     "counter", s["total_prompt_chars"])
    metric("chakra_avg_prompt_chars",   "Average prompt length in chars", "gauge",   s["avg_prompt_chars"])

    # ── Per-tenant ────────────────────────────────────────────────────────
    lines.append("# HELP chakra_tenant_blocks_total Blocks per tenant")
    lines.append("# TYPE chakra_tenant_blocks_total counter")
    for tenant, count in s["blocks_by_tenant"].items():
        lines.append(f'chakra_tenant_blocks_total{{tenant="{tenant}"}} {count}')
    lines.append("")

    lines.append("# HELP chakra_tenant_requests_total Requests per tenant")
    lines.append("# TYPE chakra_tenant_requests_total counter")
    for tenant, count in s["requests_by_tenant"].items():
        lines.append(f'chakra_tenant_requests_total{{tenant="{tenant}"}} {count}')
    lines.append("")

    # ── Layer contribution ────────────────────────────────────────────────
    lines.append("# HELP chakra_layer_avg_score Average risk score contribution per detection layer")
    lines.append("# TYPE chakra_layer_avg_score gauge")
    for layer, avg in s["layer_avg_contribution"].items():
        lines.append(f'chakra_layer_avg_score{{layer="{layer}"}} {avg}')
    lines.append("")

    lines.append("# HELP chakra_layer_dominance_pct Percentage of time each layer was dominant")
    lines.append("# TYPE chakra_layer_dominance_pct gauge")
    for layer, pct in s["layer_dominance_pct"].items():
        lines.append(f'chakra_layer_dominance_pct{{layer="{layer}"}} {pct}')
    lines.append("")

    # ── Threat categories ─────────────────────────────────────────────────
    lines.append("# HELP chakra_threat_category_total Detections per threat category")
    lines.append("# TYPE chakra_threat_category_total counter")
    for cat, cnt in s["threat_categories"].items():
        lines.append(f'chakra_threat_category_total{{category="{cat}"}} {cnt}')
    lines.append("")

    # ── Attack fingerprints ───────────────────────────────────────────────
    metric("chakra_unique_attack_fingerprints", "Unique jailbreak/attack hashes seen", "gauge",   s["unique_attack_fingerprints"])
    metric("chakra_repeated_attack_attempts",   "Repeated attack replay attempts",      "counter", s["repeated_attack_attempts"])
    metric("chakra_false_positive_count",       "Human-confirmed false positives",       "counter", s["false_positive_count"])

    # ── Risk histogram ────────────────────────────────────────────────────
    lines.append("# HELP chakra_risk_score_bucket Risk score distribution")
    lines.append("# TYPE chakra_risk_score_bucket gauge")
    for bucket, cnt in s["risk_score_histogram"].items():
        lines.append(f'chakra_risk_score_bucket{{range="{bucket}"}} {cnt}')
    lines.append("")

    return "\n".join(lines) + "\n"
