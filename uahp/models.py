# uahp/models.py
"""
SQLAlchemy models for UAHP v0.5.4
"""
from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime,
    Text, ForeignKey, Index, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

Base = declarative_base()


class Agent(Base):
    __tablename__ = "agents"

    uid = Column(String(64), primary_key=True)
    identity_json = Column(Text, nullable=False)
    manifest_json = Column(Text, nullable=False)
    reputation = Column(Float, default=0.5)
    total_tasks = Column(Integer, default=0)
    successful_tasks = Column(Integer, default=0)
    routing_state = Column(String(20), default="ACTIVE")
    routing_rights = Column(Boolean, default=False)
    sponsor_uid = Column(String(64), ForeignKey("agents.uid"), nullable=True)
    sponsee_fail_count = Column(Integer, default=0)
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_heartbeat = Column(DateTime, nullable=True)
    key_algorithm = Column(String(20), default="Ed25519")

    # Relationships
    sponsored = relationship("Sponsorship", foreign_keys="Sponsorship.sponsor_uid", back_populates="sponsor")
    sponsor_of = relationship("Sponsorship", foreign_keys="Sponsorship.sponsored_uid", back_populates="sponsored_agent")

    __table_args__ = (
        Index('idx_agents_heartbeat', 'last_heartbeat'),
        Index('idx_agents_reputation', 'reputation'),
    )


class Sponsorship(Base):
    __tablename__ = "sponsorships"

    certificate_id = Column(String(48), primary_key=True)
    sponsor_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    sponsored_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    cert_json = Column(Text, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    active = Column(Boolean, default=True)

    sponsor = relationship("Agent", foreign_keys=[sponsor_uid], back_populates="sponsored")
    sponsored_agent = relationship("Agent", foreign_keys=[sponsored_uid], back_populates="sponsor_of")

    __table_args__ = (
        Index('idx_sponsorships_expiry', 'expires_at'),
    )


class Task(Base):
    __tablename__ = "tasks"

    task_id = Column(String(64), primary_key=True)
    task_json = Column(Text, nullable=False)
    status = Column(String(20), nullable=False)
    assigned_to = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    deadline = Column(DateTime, nullable=True)
    is_encrypted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_tasks_status', 'status'),
        Index('idx_tasks_assigned', 'assigned_to'),
    )


class Receipt(Base):
    __tablename__ = "receipts"

    receipt_id = Column(String(64), primary_key=True)
    task_id = Column(String(64), ForeignKey("tasks.task_id"), nullable=False)
    agent_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    receipt_json = Column(Text, nullable=False)
    completed_at = Column(DateTime, default=datetime.utcnow)
    reputation_delta = Column(Float, nullable=False)
    output_spec_hash = Column(String(64), nullable=True)


class DeathCertificate(Base):
    __tablename__ = "death_certificates"

    cert_id = Column(String(48), primary_key=True)
    task_id = Column(String(64), ForeignKey("tasks.task_id"), nullable=False)
    agent_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    cert_json = Column(Text, nullable=False)
    expiry_reason = Column(String(20), nullable=False)
    penalty = Column(Float, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)


class ValidatorReward(Base):
    __tablename__ = "validator_rewards"

    ledger_entry_id = Column(String(48), primary_key=True)
    validator_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    task_id = Column(String(64), ForeignKey("tasks.task_id"), nullable=False)
    reward_json = Column(Text, nullable=False)
    accrued_at = Column(DateTime, default=datetime.utcnow)
    settled = Column(Boolean, default=False)


class CircuitBreaker(Base):
    __tablename__ = "circuit_breakers"

    agent_uid = Column(String(64), ForeignKey("agents.uid"), primary_key=True)
    state = Column(String(20), default="CLOSED")
    failure_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    last_failure = Column(DateTime, nullable=True)
    last_state_change = Column(DateTime, default=datetime.utcnow)
    half_open_attempts = Column(Integer, default=0)


class FailureEvent(Base):
    __tablename__ = "failures"

    event_id = Column(String(64), primary_key=True)
    agent_uid = Column(String(64), ForeignKey("agents.uid"), nullable=False)
    failure_mode = Column(String(40), nullable=False)
    task_id = Column(String(64), ForeignKey("tasks.task_id"), nullable=True)
    description = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)


class ReplayCache(Base):
    __tablename__ = "replay_cache"

    task_id = Column(String(64), primary_key=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    requester_uid = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        Index('idx_replay_expiry', 'expires_at'),
    )


class RegistryAttestation(Base):
    __tablename__ = "registry_attestations"

    attestation_id = Column(String(64), primary_key=True)
    source_registry = Column(String(64), nullable=False)
    target_registry = Column(String(64), nullable=False)
    state_root_hash = Column(String(64), nullable=False)
    checkpoint_time = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    attestation_json = Column(Text, nullable=False)


# Database setup utilities
def get_engine(db_url="sqlite:///uahp_v054_registry.db"):
    return create_engine(db_url, connect_args={"check_same_thread": False})


def get_session_maker(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(engine):
    Base.metadata.create_all(bind=engine)
