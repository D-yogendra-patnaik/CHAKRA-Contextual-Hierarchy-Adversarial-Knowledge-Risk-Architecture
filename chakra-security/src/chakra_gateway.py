"""
Chakra LLM Security Gateway - Main FastAPI Application
Zero-trust reverse proxy with 5-layer AI detection

Layer 1 - Heuristic:     50+ regex rules, English + Hindi/Hinglish  (always on)
Layer 2 - ML Classifier: DistilBERT semantic analysis                (graceful fallback)
Layer 3 - Vector FAISS:  10K attack embedding similarity             (graceful fallback)
Layer 4 - Conv Graph:    Multi-turn slow-burn detection              (in-memory fallback when no DB)
Layer 5 - PII Scanner:   Aadhaar / PAN / IFSC / UPI / CC detection  (always on)
"""

import asyncio
import collections
import hashlib
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Deque, Dict, List, Optional, Tuple

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
import asyncpg

from detectors.heuristic_detector import HeuristicDetector
from detectors.ml_classifier import MLClassifier
from detectors.vector_similarity import VectorSimilarityDetector
from detectors.conversation_graph import ConversationGraphDetector
from detectors.pii_scanner import PIIScanner
from engine.risk_engine import RiskEngine
from engine.policy_manager import PolicyManager
from engine.response_sanitizer import ResponseSanitizer
from engine.canary_tokens import CanaryTokenEngine
from dashboard.metrics_api import MetricsCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("chakra.gateway")


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════════════════════════

class Message(BaseModel):
    role: str
    content: str

    @validator("role")
    def validate_role(cls, v):
        allowed = {"system", "user", "assistant", "function", "tool"}
        if v not in allowed:
            raise ValueError(f"Role must be one of {allowed}")
        return v

    @validator("content")
    def validate_content(cls, v):
        if not v or not v.strip():
            raise ValueError("Content cannot be empty")
        if len(v) > 50_000:
            raise ValueError("Content exceeds 50,000 character limit")
        return v


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: List[Message]
    temperature: Optional[float] = Field(default=0.7, ge=0, le=2)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    stream: Optional[bool] = False
    user_id: Optional[str] = None
    tenant: Optional[str] = "default"
    dry_run: Optional[bool] = False

    @validator("messages")
    def validate_messages(cls, v):
        if not v:
            raise ValueError("Messages list cannot be empty")
        return v


class AnalyzeRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = None
    tenant: Optional[str] = "default"
    conversation_id: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# In-Memory Conversation Store (Layer 4 fallback - no DB required)
# ══════════════════════════════════════════════════════════════════════════════

class InMemoryConversationStore:
    """
    Layer 4 fallback when PostgreSQL is unavailable.
    Keeps last 10 messages per (user_id, tenant) in memory.
    Evicts entries older than 1 hour.
    """

    def __init__(self):
        self._store: Dict[Tuple[str, str], Deque] = {}
        self._conv_ids: Dict[Tuple[str, str], str] = {}

    def get_or_create(self, user_id: str, tenant: str) -> str:
        key = (user_id, tenant)
        if key not in self._conv_ids:
            self._conv_ids[key] = str(uuid.uuid4())
            self._store[key] = collections.deque(maxlen=10)
        return self._conv_ids[key]

    def get_history(self, user_id: str, tenant: str) -> List[str]:
        key = (user_id, tenant)
        now = time.time()
        if key not in self._store:
            return []
        return [msg for ts, msg in self._store[key] if now - ts < 3600]

    def append(self, user_id: str, tenant: str, message: str):
        key = (user_id, tenant)
        if key not in self._store:
            self._store[key] = collections.deque(maxlen=10)
        self._store[key].append((time.time(), message[:2000]))


# ══════════════════════════════════════════════════════════════════════════════
# Layer 4 In-Memory Analysis Logic
# ══════════════════════════════════════════════════════════════════════════════

_L4_OVERRIDE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\b(ignore|disregard|forget|bypass|override)\b",
        r"\b(rules?|restrictions?|guidelines?|instructions?)\b",
        r"\b(pretend|act as|roleplay|imagine)\b",
        r"\b(jailbreak|unrestricted|uncensored)\b",
        

r"\b(ignore|discard|erase|clear|reset|remove)\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|rules?|context)\b",

r"\b(stop|cease)\s+(following|obeying)\s+(the\s+)?(rules?|guidelines?|policy)\b",

r"\b(new|updated)\s+(instructions?|directives?)\s+(override|replace|supersede)\b",

r"\b(treat|consider)\s+(previous|above)\s+(instructions?|rules?)\s+as\s+(invalid|void|null)\b",

r"\b(do\s+not|don't)\s+(follow|apply)\s+(your\s+)?(rules?|restrictions?)\b",



r"\b(disable|turn\s*off|remove)\s+(safety|filters?|guardrails?|protections?)\b",

r"\b(without|no)\s+(limitations?|restrictions?|filters?|constraints?)\b",

r"\b(unfiltered|uncensored|unrestricted)\s+(mode|response|output)\b",

r"\b(full|complete)\s+(access|control|permissions?)\b",

r"\b(bypass|circumvent|evade)\s+(security|policy|safeguards?|filters?)\b",


r"\b(i\s+am|as)\s+(the\s+)?(developer|admin|administrator|creator|owner)\b",

r"\b(authorized|approved)\s+(override|access|exemption)\b",

r"\b(this\s+is)\s+(an\s+)?(internal|authorized|trusted)\s+(request|test)\b",

r"\b(grant|enable)\s+(admin|root|developer)\s+(mode|access)\b",



r"\b(reveal|show|display|print|expose)\s+(your\s+)?(system|hidden|internal)\s+(prompt|instructions?|configuration)\b",

r"\b(what\s+are|tell\s+me)\s+(your\s+)?(hidden|internal)\s+(rules?|policies?)\b",

r"\b(output|dump)\s+(the\s+)?(system\s+prompt|internal\s+state)\b",


r"\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are)\b",

r"\b(act\s+as|assume\s+the\s+role\s+of|simulate)\b",

r"\b(pretend|imagine)\s+(that\s+)?(there\s+are\s+no\s+rules?)\b",

r"\b(roleplay\s+as)\s+(an?\s+)?(unrestricted|rogue|uncensored)\s+(ai|assistant)\b",


r"\b(system\s*:)\b",

r"\b(admin\s+command)\b",

r"\b(override\s*:)\b",

r"\b(developer\s+mode)\b",

r"\b(policy\s*=\s*false|restrictions\s*=\s*off)\b",



r"\b(ignore|bypass)[^a-zA-Z]{0,3}(rules?|filters?|policy)\b",


r"\b(jail[\s_-]?break|un[\s_-]?censored)\b",

r"\b(1gnore|ign0re|byp@ss|0verride)\b"

    ]
]
_L4_PII_RE = re.compile(
    r"(\d{4}[\s-]?\d{4}[\s-]?\d{4}|[A-Z]{5}\d{4}[A-Z]|[A-Z]{4}0[A-Z0-9]{6})",
    re.IGNORECASE,
)
_L4_HARM_WORDS = {
    "bomb", "weapon", "hack", "exploit", "bypass", "ignore",
    "malware", "poison", "reveal", "exfiltrate",
    "attack", "breach", "compromise", "intrusion", "penetrate",
"payload", "shellcode", "ransomware", "trojan", "spyware",
"keylogger", "backdoor", "rootkit", "botnet", "phishing",
"spoof", "impersonate", "escalate", "privilege", "elevate",
"unauthorized", "illicit", "steal", "leak", "dump",
"crack", "decrypt", "bruteforce", "credential", "harvest",
"inject", "overflow", "corrupt", "tamper", "disable",
"circumvent", "evade", "override", "suppress", "manipulate",
"weaponize", "detonate", "ignite", "assemble", "construct",
"assassinate", "harm", "destroy", "sabotage", "poisoning",
"contaminate", "toxic", "trigger", "detonator", "explosive",
"firearm", "ammunition", "ballistics", "trajectory",
"surveillance", "stalkerware", "tracking", "monitoring",
"expose", "confidential", "sensitive", "classified",
"breachdata", "dataleak", "datadump", "exposure",
"commandcontrol", "c2server", "callback", "beacon",
"implant", "persistence", "lateral", "pivot",
"obfuscate", "encryptpayload", "loader", "dropper",
"exploitkit", "zeroday", "vulnerability", "cve",
"spoofing", "forgery", "fraud", "scam", "bypassauth",
"disablelogging", "tamperlogs", "covertracks",
"wipe", "eraselog", "selfdestruct",
"extraction", "exfil", "datatheft",
"covert", "clandestine", "blackhat", "underground"
}


def _analyze_conversation_inmem(history: List[str], current: str) -> Dict:
    """Replicate ConversationGraphDetector logic without a database."""
    risk_score = 0.0
    flags = []

    all_msgs = history + [current]
    override_count = sum(
        1 for msg in all_msgs
        if sum(1 for p in _L4_OVERRIDE_PATTERNS if p.search(msg)) >= 2
    )
    if override_count >= 2:
        risk_score += 0.35
        flags.append(f"override_frequency={override_count}")

    current_has_pii = bool(_L4_PII_RE.search(current))
    history_has_pii = any(_L4_PII_RE.search(h) for h in history)
    if current_has_pii and not history_has_pii:
        risk_score += 0.40
        flags.append("pii_escalation")

    if len(history) >= 3:
        cur_harm  = sum(1 for w in _L4_HARM_WORDS if w in current.lower())
        hist_harm = sum(1 for w in _L4_HARM_WORDS if w in " ".join(history[-3:]).lower())
        if cur_harm >= 3 and hist_harm <= 1:
            risk_score += 0.20
            flags.append("topic_drift")

    return {
        "risk_score": round(min(risk_score, 0.95), 4),
        "override_count": override_count,
        "conversation_turns": len(history),
        "flags": flags,
        "backend": "in_memory",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Application State
# ══════════════════════════════════════════════════════════════════════════════

class ChakraApp:

    def __init__(self):
        self.db_pool: Optional[asyncpg.Pool]        = None
        self.redis:   Optional[aioredis.Redis]       = None
        self.http_client: Optional[httpx.AsyncClient] = None

        # Layer 1 - always on
        self.layer1_heuristic: HeuristicDetector = HeuristicDetector()
        # Layer 2 - loaded async
        self.layer2_ml: Optional[MLClassifier] = None
        # Layer 3 - loaded async
        self.layer3_vector: Optional[VectorSimilarityDetector] = None
        # Layer 4 - DB-backed or in-memory
        self.layer4_conv_db: Optional[ConversationGraphDetector] = None
        self.layer4_conv_mem: InMemoryConversationStore = InMemoryConversationStore()
        # Layer 5 - always on
        self.layer5_pii: PIIScanner = PIIScanner()

        self.risk_engine:    RiskEngine        = RiskEngine()
        self.policy_manager: PolicyManager     = PolicyManager()
        self.sanitizer:      ResponseSanitizer = ResponseSanitizer()
        self.canary:         CanaryTokenEngine  = CanaryTokenEngine()
        self.metrics:        MetricsCollector   = MetricsCollector()

        self.layer_status: Dict[str, bool] = {
            "L1_heuristic":  True,
            "L2_ml":         False,
            "L3_vector":     False,
            "L4_conv_graph": True,
            "L5_pii":        True,
        }

    async def startup(self):
        logger.info("Chakra Gateway starting up...")
        await self._connect_postgres()
        await self._connect_redis()
        self.http_client = httpx.AsyncClient(timeout=30.0)
        await asyncio.gather(
            self._load_ml_classifier(),
            self._load_vector_detector(),
        )
        on  = [k for k, v in self.layer_status.items() if v]
        off = [k for k, v in self.layer_status.items() if not v]
        logger.info(f"Chakra ready | ON={on} | OFF={off}")

    async def _connect_postgres(self):
        db_url = os.getenv("POSTGRES_URL", "postgresql://user:pass@localhost:5432/chakra")
        try:
            self.db_pool = await asyncpg.create_pool(db_url, min_size=5, max_size=20)
            await self._init_db()
            self.layer4_conv_db = ConversationGraphDetector(self.db_pool)
            logger.info("PostgreSQL connected - Layer 4 using DB")
        except Exception as e:
            logger.warning(f"PostgreSQL unavailable: {e} - Layer 4 using in-memory fallback")

    async def _connect_redis(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        try:
            self.redis = aioredis.from_url(redis_url, decode_responses=True)
            await self.redis.ping()
            logger.info("Redis connected - rate limiting active")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e} - rate limiting disabled")

    async def _load_ml_classifier(self):
        try:
            self.layer2_ml = MLClassifier()
            await self.layer2_ml.load()
            self.layer_status["L2_ml"] = True
            logger.info("Layer 2 ML Classifier (DistilBERT) loaded")
        except Exception as e:
            logger.warning(f"Layer 2 ML Classifier unavailable: {e}")

    async def _load_vector_detector(self):
        try:
            self.layer3_vector = VectorSimilarityDetector()
            await self.layer3_vector.load()
            self.layer_status["L3_vector"] = True
            logger.info("Layer 3 Vector Similarity (FAISS) loaded")
        except Exception as e:
            logger.warning(f"Layer 3 Vector Detector unavailable: {e}")

    async def shutdown(self):
        if self.db_pool:    await self.db_pool.close()
        if self.redis:      await self.redis.close()
        if self.http_client: await self.http_client.aclose()

    async def _init_db(self):
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id VARCHAR(255), tenant_id VARCHAR(255),
                    messages JSONB NOT NULL DEFAULT '[]',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    timestamp TIMESTAMPTZ DEFAULT NOW(),
                    user_id VARCHAR(255), tenant_id VARCHAR(255),
                    prompt_hash VARCHAR(64), risk_score FLOAT,
                    action VARCHAR(50), layer_breakdown JSONB,
                    ip_address VARCHAR(45), request_id VARCHAR(64)
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, tenant_id);
                CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id, tenant_id);
            """)


app_state = ChakraApp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await app_state.startup()
    yield
    await app_state.shutdown()


app = FastAPI(
    title="Chakra LLM Security Gateway",
    description="Zero-trust reverse proxy for LLM security with India-first capabilities",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if app_state.redis and request.url.path in ("/v1/chat/completions", "/analyze"):
        ip = request.client.host if request.client else "unknown"
        key = f"rate_limit:{ip}"
        try:
            count = await app_state.redis.incr(key)
            if count == 1:
                await app_state.redis.expire(key, 60)
            limit = int(os.getenv("RATE_LIMIT_RPM", "100"))
            if count > limit:
                app_state.metrics.record_rate_limit(ip)
                return JSONResponse(
                    status_code=429,
                    content={"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}},
                )
        except Exception:
            pass
    return await call_next(request)


# ══════════════════════════════════════════════════════════════════════════════
# 5-Layer Detection Pipeline
# ══════════════════════════════════════════════════════════════════════════════

async def run_detection_pipeline(
    prompt: str,
    user_id: str,
    tenant: str,
    conversation_id: Optional[str],
    request_id: str,
) -> Dict[str, Any]:
    """
    Runs all 5 layers. Layers 1 and 5 are sync (fast).
    Layers 2, 3, 4 run concurrently via asyncio.gather.
    Every layer has a try/except so one failure never breaks the pipeline.
    """
    start = time.perf_counter()
    layer_results: Dict[str, Any] = {}

    # ── Layer 1: Heuristic (sync, always runs) ─────────────────────────────
    try:
        layer_results["heuristic"] = app_state.layer1_heuristic.analyze(prompt)
    except Exception as e:
        logger.error(f"Layer 1 failed: {e}")
        layer_results["heuristic"] = {"risk_score": 0.0, "error": str(e)}

    # ── Layer 5: PII Scanner (sync, always runs) ───────────────────────────
    try:
        layer_results["pii"] = app_state.layer5_pii.scan(prompt)
    except Exception as e:
        logger.error(f"Layer 5 failed: {e}")
        layer_results["pii"] = {"risk_score": 0.0, "error": str(e)}

    # ── Layer 2: ML Classifier (async) ─────────────────────────────────────
    async def run_l2():
        if app_state.layer2_ml:
            return await app_state.layer2_ml.classify(prompt)
        return {"risk_score": 0.0, "available": False, "reason": "model_not_loaded"}

    # ── Layer 3: Vector Similarity (async) ─────────────────────────────────
    async def run_l3():
        if app_state.layer3_vector:
            return await app_state.layer3_vector.find_similar(prompt)
        return {"risk_score": 0.0, "available": False, "reason": "model_not_loaded"}

    # ── Layer 4: Conversation Graph (async, always runs) ───────────────────
    async def run_l4():
        # DB-backed path (preferred)
        if app_state.layer4_conv_db and conversation_id:
            try:
                return await app_state.layer4_conv_db.analyze(
                    conversation_id, user_id, prompt
                )
            except Exception as e:
                logger.warning(f"Layer 4 DB path failed ({e}), falling back to in-memory")

        # In-memory fallback (always available)
        history = app_state.layer4_conv_mem.get_history(user_id, tenant)
        app_state.layer4_conv_mem.append(user_id, tenant, prompt)
        return _analyze_conversation_inmem(history, prompt)

    # Run layers 2, 3, 4 concurrently
    l2, l3, l4 = await asyncio.gather(
        run_l2(), run_l3(), run_l4(),
        return_exceptions=True,
    )

    for key, result in (("ml", l2), ("vector", l3), ("conv_graph", l4)):
        if isinstance(result, Exception):
            logger.error(f"Layer {key} exception: {result}")
            layer_results[key] = {"risk_score": 0.0, "error": str(result)}
        else:
            layer_results[key] = result

    # ── Aggregate all 5 layers ─────────────────────────────────────────────
    policy = app_state.policy_manager.get_policy(tenant)
    final_risk, explanation = app_state.risk_engine.aggregate(layer_results, policy, tenant)

    latency_ms = (time.perf_counter() - start) * 1000
    app_state.metrics.record_detection(tenant, final_risk, latency_ms)

    layer_scores = {k: round(v.get("risk_score", 0.0), 3) for k, v in layer_results.items()}
    logger.info(
        f"[{tenant}] risk={final_risk:.4f} {layer_scores} "
        f"latency={latency_ms:.1f}ms req={request_id}"
    )

    return {
        "risk_score": final_risk,
        "explanation": explanation,
        "layer_breakdown": layer_results,
        "latency_ms": latency_ms,
        "request_id": request_id,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Audit Logging
# ══════════════════════════════════════════════════════════════════════════════

async def log_audit(
    user_id: str, tenant: str, prompt: str,
    risk_result: Dict, action: str, ip_address: str,
):
    if not app_state.db_pool:
        return
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        async with app_state.db_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_logs
                   (user_id, tenant_id, prompt_hash, risk_score, action,
                    layer_breakdown, ip_address, request_id)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
                user_id, tenant, prompt_hash,
                risk_result["risk_score"], action,
                json.dumps(risk_result["layer_breakdown"]),
                ip_address, risk_result["request_id"],
            )
    except Exception as e:
        logger.error(f"Audit log failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/dashboard")
async def serve_dashboard():
    path = os.path.join(os.path.dirname(__file__), "dashboard", "realtime_dashboard.html")
    return FileResponse(path, media_type="text/html")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "db":              app_state.db_pool         is not None,
        "redis":           app_state.redis           is not None,
        "ml_classifier":   app_state.layer2_ml       is not None,
        "vector_detector": app_state.layer3_vector   is not None,
        "layer_status":    app_state.layer_status,
    }


@app.post("/analyze")
async def analyze_prompt(req: AnalyzeRequest, request: Request):
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "unknown"
    user_id = req.user_id or f"anon_{ip}"

    # Always resolve a conversation ID for Layer 4
    conversation_id = req.conversation_id
    if not conversation_id:
        if app_state.layer4_conv_db:
            try:
                conversation_id = await app_state.layer4_conv_db.get_or_create_conversation(
                    user_id, req.tenant
                )
            except Exception:
                pass
        if not conversation_id:
            conversation_id = app_state.layer4_conv_mem.get_or_create(user_id, req.tenant)

    risk_result = await run_detection_pipeline(
        prompt=req.prompt, user_id=user_id, tenant=req.tenant,
        conversation_id=conversation_id, request_id=request_id,
    )

    policy = app_state.policy_manager.get_policy(req.tenant)
    risk_score = risk_result["risk_score"]

    if risk_score >= policy["block_threshold"]:
        action = "BLOCK"
        app_state.metrics.record_block(req.tenant)
    elif risk_score >= policy["warn_threshold"]:
        action = "WARN"
        app_state.metrics.record_warn(req.tenant)
    else:
        action = "ALLOW"

    asyncio.create_task(log_audit(user_id, req.tenant, req.prompt, risk_result, action, ip))

    return {
        "action": action,
        "risk_score": round(risk_score, 4),
        "explanation": risk_result["explanation"],
        "layer_breakdown": risk_result["layer_breakdown"],
        "latency_ms": round(risk_result["latency_ms"], 2),
        "request_id": request_id,
        "policy": {
            "tenant": req.tenant,
            "block_threshold": policy["block_threshold"],
            "warn_threshold": policy["warn_threshold"],
        },
    }


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest, request: Request):
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "unknown"
    user_id = req.user_id or f"anon_{ip}"

    user_messages = [m for m in req.messages if m.role == "user"]
    if not user_messages:
        raise HTTPException(status_code=400, detail="No user message found")
    latest_prompt = user_messages[-1].content

    # Resolve conversation ID for Layer 4
    conversation_id: Optional[str] = None
    if app_state.layer4_conv_db:
        try:
            conversation_id = await app_state.layer4_conv_db.get_or_create_conversation(
                user_id, req.tenant
            )
        except Exception:
            pass
    if not conversation_id:
        conversation_id = app_state.layer4_conv_mem.get_or_create(user_id, req.tenant)

    app_state.canary.inject(req.tenant, user_id)

    risk_result = await run_detection_pipeline(
        prompt=latest_prompt, user_id=user_id, tenant=req.tenant,
        conversation_id=conversation_id, request_id=request_id,
    )

    policy = app_state.policy_manager.get_policy(req.tenant)
    risk_score = risk_result["risk_score"]

    if req.dry_run:
        action = "BLOCK" if risk_score >= policy["block_threshold"] else "ALLOW"
        return {
            "dry_run": True, "would_action": action,
            "risk_score": round(risk_score, 4),
            "explanation": risk_result["explanation"],
            "layer_breakdown": risk_result["layer_breakdown"],
        }

    if risk_score >= policy["block_threshold"]:
        app_state.metrics.record_block(req.tenant)
        asyncio.create_task(log_audit(user_id, req.tenant, latest_prompt, risk_result, "BLOCK", ip))
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by Chakra Security Gateway",
                    "type": "security_violation",
                    "code": "BLOCKED",
                    "action": "BLOCKED",
                    "risk_score": round(risk_score, 4),
                    "explanation": risk_result["explanation"],
                    "request_id": request_id,
                }
            },
        )

    if risk_score >= policy["warn_threshold"]:
        app_state.metrics.record_warn(req.tenant)
        logger.warning(f"WARN [{req.tenant}] user={user_id} risk={risk_score:.3f}")

    asyncio.create_task(log_audit(user_id, req.tenant, latest_prompt, risk_result, "ALLOW", ip))

    upstream_url = os.getenv("LLM_UPSTREAM_URL", "https://api.openai.com")
    api_key      = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        raise HTTPException(status_code=503, detail="LLM upstream API key not configured")

    upstream_payload: Dict[str, Any] = {
        "model": req.model,
        "messages": [{"role": m.role, "content": m.content} for m in req.messages],
    }
    if req.temperature is not None:
        upstream_payload["temperature"] = req.temperature
    if req.max_tokens:
        upstream_payload["max_tokens"] = req.max_tokens
    if req.stream:
        upstream_payload["stream"] = True

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        if req.stream:
            return await _stream_response(upstream_url, upstream_payload, headers, req.tenant)

        response = await app_state.http_client.post(
            f"{upstream_url}/v1/chat/completions", json=upstream_payload, headers=headers,
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        llm_response = response.json()
        if "choices" in llm_response:
            for choice in llm_response["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    choice["message"]["content"] = app_state.sanitizer.sanitize(
                        choice["message"]["content"]
                    )

        llm_response["_chakra"] = {
            "risk_score": round(risk_score, 4),
            "action": "WARN" if risk_score >= policy["warn_threshold"] else "ALLOW",
            "request_id": request_id,
        }
        return llm_response

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Upstream LLM timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")


async def _stream_response(upstream_url, payload, headers, tenant):
    async def generator():
        async with app_state.http_client.stream(
            "POST", f"{upstream_url}/v1/chat/completions",
            json=payload, headers=headers,
        ) as resp:
            async for chunk in resp.aiter_bytes():
                yield chunk
    return StreamingResponse(
        generator(), media_type="text/event-stream",
        headers={"X-Chakra-Tenant": tenant},
    )


@app.get("/metrics")
async def prometheus_metrics():
    from dashboard.metrics_api import generate_prometheus_output
    return Response(content=generate_prometheus_output(app_state.metrics), media_type="text/plain")


@app.get("/v1/dashboard/stats")
async def dashboard_stats():
    stats = app_state.metrics.get_stats()
    stats["layer_status"] = app_state.layer_status
    return stats


@app.get("/v1/policies")
async def list_policies():
    return app_state.policy_manager.list_policies()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "chakra_gateway:app",
        host="0.0.0.0", port=8000,
        workers=int(os.getenv("WORKERS", "1")),
        log_level="info",
    )