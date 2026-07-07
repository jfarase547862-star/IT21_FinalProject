CREATE TABLE IF NOT EXISTS role (
    role_id VARCHAR(32) PRIMARY KEY,
    role_name VARCHAR(128) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS "user" (
    user_id VARCHAR(64) PRIMARY KEY,
    first_name VARCHAR(128) NOT NULL,
    last_name VARCHAR(128) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role_id VARCHAR(32) NOT NULL REFERENCES role(role_id),
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS document (
    document_id VARCHAR(64) PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    document_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_size BIGINT NOT NULL DEFAULT 0,
    file_hash_original TEXT
);

CREATE TABLE IF NOT EXISTS signing_key (
    key_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    key_type VARCHAR(32) NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS digital_signature (
    signature_id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL,
    signer_id VARCHAR(64) NOT NULL,
    signature_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    signature_value TEXT NOT NULL,
    signed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    key_id VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS verification_log (
    verification_id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL,
    verifier_id VARCHAR(64) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remarks TEXT NOT NULL
);
