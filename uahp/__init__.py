"""UAHP v0.5.4"""
from .identity import Agent
from .capability import CapabilityBuilder, perform_handshake, can_handle
from .intent import TaskBuilder, resolve_intent
from .session import SecureSession
from .verification import (generate_receipt, verify_receipt,
    calculate_trust_score, issue_death_certificate, exponential_sponsor_penalty)
from .canon import canonical_encode, canonical_hash, run_test_vectors
from .enums import (IntentType, DataFormat, AgentPlatform, TaskStatus,
    AmbiguityPolicy, FailureMode, CircuitState, TaskExpiry)
from .schemas import (
    AgentIdentity, CapabilityManifest, TaskPacket,
    CompletionReceipt, SponsorshipCertificate, ValidatorRewardEntry,
    AmbiguityResponse, DeathCertificate, EncryptedTaskPacket, EphemeralKeyPacket,
    RegistryAttestation,  # NEW
    CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    HEARTBEAT_TIMEOUT_HOURS, SPONSORSHIP_VALIDITY_DAYS, MAX_REPLAY_TTL_HOURS
)

# Server imports (optional - only if running API)
try:
    from .server import app, get_db
    from .models import init_db, get_engine
except ImportError:
    pass  # FastAPI/SQLAlchemy not installed

__version__ = "0.5.4"
