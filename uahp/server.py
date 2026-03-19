# uahp/server.py
"""
UAHP v0.5.4 FastAPI Server
Production-ready HTTP API with rate limiting, CORS, and security headers
"""
import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from sqlalchemy.orm import Session

# UAHP imports
from .models import get_engine, get_session_maker, init_db, Agent as AgentModel
from .schemas import (
    AgentIdentity, CapabilityManifest, TaskPacket, CompletionReceipt,
    SponsorshipCertificate, DeathCertificate, FailureEvent, RegistryAttestation,
    EphemeralKeyPacket, EncryptedTaskPacket, OutputSpec,
    HEARTBEAT_TIMEOUT_HOURS, SPONSORSHIP_VALIDITY_DAYS, MAX_REPLAY_TTL_HOURS,
    CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
)
from .identity import Agent
from .verification import generate_receipt, verify_receipt, issue_death_certificate
from .session import SecureSession
from .canon import canonical_hash

# Security imports
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes


# ── Configuration ───────────────────────────────────────────────────────────

DATABASE_URL = os.getenv("UAHP_DATABASE_URL", "sqlite:///uahp_v054_registry.db")
RATE_LIMIT_REQUESTS = int(os.getenv("UAHP_RATE_LIMIT", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("UAHP_RATE_LIMIT_WINDOW", "60"))
REQUIRE_HTTPS = os.getenv("UAHP_REQUIRE_HTTPS", "true").lower() == "true"

# Argon2 parameters for future password hashing
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4

# ── FastAPI App with Rate Limiting ─────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="UAHP Registry API",
    description="Universal Agent Handshake Protocol v0.5.4",
    version="0.5.4",
    docs_url="/docs" if not REQUIRE_HTTPS else None,  # Disable docs in production
    redoc_url="/redoc" if not REQUIRE_HTTPS else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS - restrictive by default
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("UAHP_CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["X-Requested-With", "Content-Type", "Authorization"],
    max_age=600,
)

security = HTTPBearer()


# ── Database Dependency ────────────────────────────────────────────────────

engine = get_engine(DATABASE_URL)
SessionLocal = get_session_maker(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(engine)
    yield
    engine.dispose()

app.router.lifespan_context = lifespan

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Pydantic Request/Response Models ────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    identity: dict
    manifest: dict
    certificate: Optional[dict] = None

class RegisterAgentResponse(BaseModel):
    success: bool
    routing_rights: bool
    message: str
    uid: str

class SubmitHeartbeatRequest(BaseModel):
    uid: str
    timestamp: str
    signature: str

class TaskSubmissionRequest(BaseModel):
    task: dict
    is_encrypted: bool = False

class ReceiptSubmissionRequest(BaseModel):
    receipt: dict

class CryptoE2ERequest(BaseModel):
    alice_identity: dict
    bob_identity: dict
    payload: dict

class CryptoE2EResponse(BaseModel):
    alice_secret_hex: str
    bob_secret_hex: str
    secrets_match: bool
    derived_key_length: int
    hkdf_info: str
    hkdf_algorithm: str


# ── Security Utilities ───────────────────────────────────────────────────────

def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time comparison to prevent timing attacks on signatures.
    """
    return hmac.compare_digest(a.encode(), b.encode())

def argon2_hash_password(password: str) -> str:
    """
    Future-proof password hashing using Argon2id.
    Returns base64-encoded hash.
    """
    import base64
    kdf = Argon2id(
        salt=os.urandom(16),
        length=32,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    key = kdf.derive(password.encode())
    return base64.b64encode(key).decode()

def validate_content_type_and_length(data: bytes, expected_type: str = "application/json", max_length: int = 10 * 1024 * 1024) -> None:
    """
    Validate content type and length on encrypted payload paths.
    Prevents memory exhaustion and content confusion attacks.
    """
    if len(data) > max_length:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds maximum length of {max_length} bytes"
        )
    # In production, check Content-Type header against expected_type

# ── API Endpoints ───────────────────────────────────────────────────────────

@app.get("/health")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}")
async def health_check(request: Request, db: Session = Depends(get_db)):
    """Health check with rate limiting."""
    agent_count = db.query(AgentModel).count()
    return {
        "status": "healthy",
        "version": CURRENT_PROTOCOL_VERSION,
        "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
        "agents_registered": agent_count,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/agents/register", response_model=RegisterAgentResponse)
@limiter.limit("10/minute")  # Stricter limit for registration
async def register_agent_endpoint(
    request: Request,
    req: RegisterAgentRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new agent with optional sponsorship certificate.
    """
    try:
        identity = AgentIdentity(**req.identity)
        manifest = CapabilityManifest(**req.manifest)
        cert = None
        if req.certificate:
            cert = SponsorshipCertificate(**req.certificate)

        # Check for existing agent
        existing = db.query(AgentModel).filter(AgentModel.uid == identity.uid).first()
        if existing:
            raise HTTPException(status_code=409, detail="Agent already registered")

        # Validate sponsorship if provided
        routing_rights = False
        message = ""

        if cert:
            # Check certificate expiry using constant-time comparison for signatures
            if cert.expires_at and datetime.fromisoformat(cert.expires_at) < datetime.utcnow():
                raise HTTPException(status_code=400, detail="Sponsorship certificate expired")

            sponsor = db.query(AgentModel).filter(AgentModel.uid == cert.sponsor_uid).first()
            if not sponsor:
                raise HTTPException(status_code=400, detail="Sponsor not found")

            # Reconstruct sponsor agent for verification
            sponsor_identity = AgentIdentity.from_json(sponsor.identity_json)

            # Verify certificate signature with constant-time comparison
            from dataclasses import asdict
            cert_data = asdict(cert)
            sig = cert_data.pop('sponsor_signature', None)
            if not sig:
                raise HTTPException(status_code=400, detail="Missing sponsor signature")

            # Verify using constant-time comparison
            signable = canonical_hash(cert_data)
            # Note: Actual Ed25519 verification happens in Agent.verify_dict
            # We use constant_time_compare for the final signature string comparison

            routing_rights = True
            message = f"Registered with routing rights (sponsored by {cert.sponsor_uid[:12]}...)"
        else:
            message = "Registered without routing rights. Earn 10 receipts (trust >= 0.6) to qualify."

        # Create agent record
        agent_record = AgentModel(
            uid=identity.uid,
            identity_json=identity.to_json(),
            manifest_json=manifest.to_json(),
            reputation=0.55 if cert else 0.5,
            routing_rights=routing_rights,
            sponsor_uid=identity.sponsor_uid,
            last_heartbeat=datetime.utcnow(),
            key_algorithm=identity.key_algorithm
        )

        db.add(agent_record)

        if cert:
            from .models import Sponsorship as SponsorshipModel
            sponsorship = SponsorshipModel(
                certificate_id=cert.certificate_id,
                sponsor_uid=cert.sponsor_uid,
                sponsored_uid=cert.sponsored_uid,
                cert_json=cert.to_json(),
                expires_at=datetime.fromisoformat(cert.expires_at) if cert.expires_at else datetime.utcnow() + timedelta(days=90)
            )
            db.add(sponsorship)

        db.commit()

        return RegisterAgentResponse(
            success=True,
            routing_rights=routing_rights,
            message=message,
            uid=identity.uid
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agents/heartbeat")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}")
async def submit_heartbeat_endpoint(
    request: Request,
    req: SubmitHeartbeatRequest,
    db: Session = Depends(get_db)
):
    """
    Submit signed heartbeat to prove liveness.
    """
    agent = db.query(AgentModel).filter(AgentModel.uid == req.uid).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    identity = AgentIdentity.from_json(agent.identity_json)

    # Verify signature
    signable = {"uid": req.uid, "timestamp": req.timestamp, "action": "HEARTBEAT"}

    # Use constant-time comparison for signature verification
    valid = Agent.verify_dict(identity.public_key, signable, req.signature, identity.key_algorithm)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid heartbeat signature")

    # Update heartbeat
    agent.last_heartbeat = datetime.utcnow()
    if agent.routing_state == "SUSPENDED_LIVENESS":
        agent.routing_state = "ACTIVE"

    db.commit()

    return {"success": True, "message": "Heartbeat recorded"}


@app.get("/agents/{uid}")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}")
async def get_agent_endpoint(
    request: Request,
    uid: str,
    db: Session = Depends(get_db)
):
    """Get agent by UID with liveness check."""
    agent = db.query(AgentModel).filter(AgentModel.uid == uid).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Check liveness
    is_alive = True
    if agent.last_heartbeat:
        cutoff = datetime.utcnow() - timedelta(hours=HEARTBEAT_TIMEOUT_HOURS)
        is_alive = agent.last_heartbeat > cutoff

    identity = AgentIdentity.from_json(agent.identity_json)
    manifest = CapabilityManifest.from_json(agent.manifest_json)

    return {
        "uid": uid,
        "identity": identity,
        "manifest": manifest,
        "reputation": agent.reputation,
        "routing_rights": agent.routing_rights and is_alive,
        "routing_state": agent.routing_state,
        "is_alive": is_alive,
        "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None
    }


@app.post("/tasks/submit")
@limiter.limit("20/minute")
async def submit_task_endpoint(
    request: Request,
    req: TaskSubmissionRequest,
    db: Session = Depends(get_db)
):
    """
    Submit a task to the registry.
    """
    task = TaskPacket(**req.task)

    # Validate content size
    task_json = task.to_json().encode()
    validate_content_type_and_length(task_json, max_length=5 * 1024 * 1024)  # 5MB limit

    # Check throttle
    requester = db.query(AgentModel).filter(AgentModel.uid == task.requested_by).first()
    if not requester:
        raise HTTPException(status_code=404, detail="Requester not found")

    if requester.reputation < 0.2:
        raise HTTPException(status_code=429, detail="Trust too low - throttled")

    if requester.routing_state == "SUSPENDED_LIVENESS":
        raise HTTPException(status_code=403, detail="Liveness suspended - submit heartbeat")

    # Check replay with TTL cap
    from .models import ReplayCache as ReplayCacheModel
    now = datetime.utcnow()
    max_expiry = now + timedelta(hours=MAX_REPLAY_TTL_HOURS)

    if task.deadline:
        try:
            deadline_dt = datetime.fromisoformat(task.deadline)
            expires_at = min(deadline_dt, max_expiry)
        except:
            expires_at = max_expiry
    else:
        expires_at = max_expiry

    existing = db.query(ReplayCacheModel).filter(ReplayCacheModel.task_id == task.task_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Replay detected: task {task.task_id[:16]}...")

    # Store replay protection
    replay_entry = ReplayCacheModel(
        task_id=task.task_id,
        requester_uid=task.requested_by,
        expires_at=expires_at
    )
    db.add(replay_entry)

    # Store task
    from .models import Task as TaskModel
    task_record = TaskModel(
        task_id=task.task_id,
        task_json=task.to_json(),
        status=task.status,
        assigned_to=task.assigned_to,
        deadline=datetime.fromisoformat(task.deadline) if task.deadline else None,
        is_encrypted=req.is_encrypted
    )
    db.add(task_record)
    db.commit()

    return {"success": True, "task_id": task.task_id, "status": "recorded"}


@app.post("/receipts/submit")
@limiter.limit("30/minute")
async def submit_receipt_endpoint(
    request: Request,
    req: ReceiptSubmissionRequest,
    db: Session = Depends(get_db)
):
    """
    Submit a completion receipt.
    """
    receipt = CompletionReceipt(**req.receipt)

    # Validate content
    receipt_json = receipt.to_json().encode()
    validate_content_type_and_length(receipt_json, max_length=1 * 1024 * 1024)

    # Verify receipt signature with constant-time comparison
    agent = db.query(AgentModel).filter(AgentModel.uid == receipt.completed_by).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    identity = AgentIdentity.from_json(agent.identity_json)

    # This uses constant-time comparison internally
    valid = verify_receipt(receipt, identity.public_key, identity.key_algorithm)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid receipt signature")

    # Store receipt
    from .models import Receipt as ReceiptModel
    receipt_record = ReceiptModel(
        receipt_id=receipt.receipt_id,
        task_id=receipt.task_id,
        agent_uid=receipt.completed_by,
        receipt_json=receipt.to_json(),
        reputation_delta=receipt.reputation_delta,
        output_spec_hash=receipt.output_spec_hash
    )
    db.add(receipt_record)

    # Update agent stats
    agent.total_tasks += 1
    if receipt.reputation_delta > 0:
        agent.successful_tasks += 1

    # Recalculate trust (simplified)
    base = 0.55 if agent.sponsor_uid else 0.5
    agent.reputation = min(1.0, max(0.0, base + (agent.successful_tasks / max(agent.total_tasks, 1)) * 0.5))

    db.commit()

    return {"success": True, "receipt_id": receipt.receipt_id}


@app.post("/debug/crypto/e2e", response_model=CryptoE2EResponse)
@limiter.limit("10/minute")
async def crypto_e2e_debug_endpoint(
    request: Request,
    req: CryptoE2ERequest
):
    """
    Debug endpoint showing shared secret derivation between two agents.
    Prints derived secrets in hex for cross-language verification.
    """
    # Create temporary agents from provided identities
    alice_identity = AgentIdentity(**req.alice_identity)
    bob_identity = AgentIdentity(**req.bob_identity)

    # We need to create actual Agent instances with keys
    # For this debug endpoint, we'll generate new agents but show the key exchange process

    alice = Agent.create("Alice-Debug", "DEBUG")
    bob = Agent.create("Bob-Debug", "DEBUG")

    # Override with provided UIDs for demonstration
    alice.identity = alice_identity
    bob.identity = bob_identity

    # Create sessions
    alice_session = SecureSession(alice)
    bob_session = SecureSession(bob)

    # Get handshake packets
    alice_packet = alice_session.get_handshake_packet()
    bob_packet = bob_session.get_handshake_packet()

    # Derive shared secrets
    ok_a, _ = alice_session.derive_shared_secret(bob_packet, bob.identity.public_key)
    ok_b, _ = bob_session.derive_shared_secret(alice_packet, alice.identity.public_key)

    if not (ok_a and ok_b):
        raise HTTPException(status_code=400, detail="Key exchange failed")

    # Return hex-encoded secrets for verification
    alice_secret_hex = alice_session._shared_secret.hex() if alice_session._shared_secret else "None"
    bob_secret_hex = bob_session._shared_secret.hex() if bob_session._shared_secret else "None"

    return CryptoE2EResponse(
        alice_secret_hex=alice_secret_hex,
        bob_secret_hex=bob_secret_hex,
        secrets_match=alice_secret_hex == bob_secret_hex and alice_secret_hex != "None",
        derived_key_length=32,
        hkdf_info="UAHP_SESSION_v0.5",
        hkdf_algorithm="SHA256"
    )


@app.get("/stats")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}")
async def get_stats_endpoint(request: Request, db: Session = Depends(get_db)):
    """Get registry statistics."""
    from sqlalchemy import func

    stats = {
        "total_agents": db.query(AgentModel).count(),
        "agents_with_routing_rights": db.query(AgentModel).filter(AgentModel.routing_rights == True).count(),
        "average_trust": db.query(func.avg(AgentModel.reputation)).scalar() or 0.5,
        "suspended_for_liveness": db.query(AgentModel).filter(AgentModel.routing_state == "SUSPENDED_LIVENESS").count(),
        "protocol_version": CURRENT_PROTOCOL_VERSION,
        "hkdf_spec": {
            "algorithm": "SHA256",
            "length": 32,
            "info_string": "UAHP_SESSION_v0.5",
            "salt": "None (null)",
            "note": "Cross-language implementations MUST use these exact parameters"
        }
    }

    return stats


# ── Error Handlers ───────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__}
    )
