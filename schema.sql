-- UAHP v0.5.4 Database Schema
-- Run this directly or use Alembic migrations

-- Agents table
CREATE TABLE IF NOT EXISTS agents (
    uid TEXT PRIMARY KEY,
    identity_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    reputation REAL DEFAULT 0.5,
    total_tasks INTEGER DEFAULT 0,
    successful_tasks INTEGER DEFAULT 0,
    routing_state TEXT DEFAULT 'ACTIVE',
    routing_rights INTEGER DEFAULT 0,
    sponsor_uid TEXT,
    sponsee_fail_count INTEGER DEFAULT 0,
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT,
    key_algorithm TEXT DEFAULT 'Ed25519'
);

CREATE INDEX idx_agents_heartbeat ON agents(last_heartbeat);
CREATE INDEX idx_agents_reputation ON agents(reputation);

-- Sponsorships with expiry
CREATE TABLE IF NOT EXISTS sponsorships (
    certificate_id TEXT PRIMARY KEY,
    sponsor_uid TEXT NOT NULL,
    sponsored_uid TEXT NOT NULL,
    cert_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    active INTEGER DEFAULT 1
);

CREATE INDEX idx_sponsorships_expiry ON sponsorships(expires_at);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    task_json TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_to TEXT NOT NULL,
    deadline TEXT,
    is_encrypted INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_assigned ON tasks(assigned_to);

-- Receipts with output_spec_hash
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    agent_uid TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    reputation_delta REAL NOT NULL,
    output_spec_hash TEXT
);

-- Death certificates
CREATE TABLE IF NOT EXISTS death_certificates (
    cert_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    agent_uid TEXT NOT NULL,
    cert_json TEXT NOT NULL,
    expiry_reason TEXT NOT NULL,
    penalty REAL NOT NULL,
    issued_at TEXT NOT NULL
);

-- Validator rewards
CREATE TABLE IF NOT EXISTS validator_rewards (
    ledger_entry_id TEXT PRIMARY KEY,
    validator_uid TEXT NOT NULL,
    task_id TEXT NOT NULL,
    reward_json TEXT NOT NULL,
    accrued_at TEXT NOT NULL,
    settled INTEGER DEFAULT 0
);

-- Circuit breakers
CREATE TABLE IF NOT EXISTS circuit_breakers (
    agent_uid TEXT PRIMARY KEY,
    state TEXT DEFAULT 'CLOSED',
    failure_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    last_failure TEXT,
    last_state_change TEXT NOT NULL,
    half_open_attempts INTEGER DEFAULT 0
);

-- Failure events
CREATE TABLE IF NOT EXISTS failures (
    event_id TEXT PRIMARY KEY,
    agent_uid TEXT NOT NULL,
    failure_mode TEXT NOT NULL,
    task_id TEXT,
    description TEXT,
    timestamp TEXT NOT NULL
);

-- Replay protection with TTL
CREATE TABLE IF NOT EXISTS replay_cache (
    task_id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    requester_uid TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_replay_expiry ON replay_cache(expires_at);

-- Registry federation attestations
CREATE TABLE IF NOT EXISTS registry_attestations (
    attestation_id TEXT PRIMARY KEY,
    source_registry TEXT NOT NULL,
    target_registry TEXT NOT NULL,
    state_root_hash TEXT NOT NULL,
    checkpoint_time TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attestation_json TEXT NOT NULL
);
