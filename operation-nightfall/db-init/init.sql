-- ============================================================
-- NovaCorp DevPortal — Database Initialization
-- PostgreSQL schema, seed data, and the flag encryption key
-- ============================================================

-- Enable pgcrypto FIRST so digest() is available
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Clean start
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS secrets CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ============================================================
-- Users table
-- ============================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'developer',
    email VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Admin user (password: Adm1n_N0v4_2024!)
INSERT INTO users (username, password_hash, role, email) VALUES
    ('admin', encode(digest('Adm1n_N0v4_2024!', 'sha256'), 'hex'), 'admin', 'admin@novacorp.internal');

-- Developer user (password: N0v4D3v2024)
INSERT INTO users (username, password_hash, role, email) VALUES
    ('developer', encode(digest('N0v4D3v2024', 'sha256'), 'hex'), 'developer', 'dev@novacorp.internal');

-- Additional realistic users
INSERT INTO users (username, password_hash, role, email) VALUES
    ('jenkins-ci', encode(digest('ci_s3rv1c3_2024', 'sha256'), 'hex'), 'service', 'ci@novacorp.internal'),
    ('monitoring', encode(digest('m0n1t0r_2024', 'sha256'), 'hex'), 'service', 'monitoring@novacorp.internal'),
    ('sarah.chen', encode(digest('s4r4h_ch3n_pwd', 'sha256'), 'hex'), 'developer', 'sarah.chen@novacorp.internal'),
    ('raj.patel', encode(digest('r4j_p4t3l_pwd', 'sha256'), 'hex'), 'developer', 'raj.patel@novacorp.internal');

-- ============================================================
-- Projects table
-- ============================================================
CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    owner_id INTEGER REFERENCES users(id),
    status VARCHAR(32) DEFAULT 'active',
    health INTEGER DEFAULT 100,
    last_deploy TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    repository_url VARCHAR(256),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO projects (name, description, owner_id, status, health, last_deploy) VALUES
    ('payment-gateway', 'Core payment processing service handling UPI, NEFT, and card transactions', 1, 'active', 98, NOW() - INTERVAL '2 hours'),
    ('kyc-service', 'Know Your Customer verification and document processing pipeline', 1, 'active', 95, NOW() - INTERVAL '6 hours'),
    ('fraud-detection', 'Real-time transaction fraud detection using ML models', 5, 'active', 100, NOW() - INTERVAL '1 day'),
    ('notification-hub', 'Multi-channel notification service (SMS, email, push)', 2, 'active', 92, NOW() - INTERVAL '3 hours'),
    ('lending-platform', 'Digital lending and credit scoring platform', 6, 'staging', 87, NOW() - INTERVAL '4 hours'),
    ('merchant-portal', 'Self-service portal for merchant onboarding and management', 5, 'active', 99, NOW() - INTERVAL '12 hours');

-- ============================================================
-- Secrets table — contains the flag encryption key
-- This is what players extract via Blind SQLi (Step 3)
-- ============================================================
CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    secret_name VARCHAR(128) UNIQUE NOT NULL,
    secret_value TEXT NOT NULL,
    description TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO secrets (secret_name, secret_value, description, created_by) VALUES
    ('jwt_signing_key', 's3cr3t_jwt_n0v4c0rp_k3y_d0_n0t_l34k', 'JWT token signing key for auth service', 1),
    ('flag_encryption_key', 'n1ghtf4ll_k3y_x7q9', 'Encryption key for sensitive data exports', 1),
    ('stripe_api_key', 'sk_test_fake_key_for_ctf_challenge_only123', 'Stripe payment API key (test mode)', 1),
    ('sendgrid_key', 'SG.fake_key_for_ctf_challenge_only', 'SendGrid email API key', 1),
    ('aws_access_key_id', 'AKIAIOSFODNN7EXAMPLE', 'AWS access key for S3 uploads', 1),
    ('database_master_password', 'N0v4C0rp_Pg_2024!', 'PostgreSQL master password', 1);

-- ============================================================
-- Audit logs table
-- ============================================================
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(64) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    details JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Seed some audit logs to make it look realistic
INSERT INTO audit_logs (action, user_id, details, ip_address, created_at) VALUES
    ('login_success', 1, '{"username": "admin"}', '10.0.1.5', NOW() - INTERVAL '3 hours'),
    ('login_success', 2, '{"username": "developer"}', '10.0.1.12', NOW() - INTERVAL '5 hours'),
    ('project_deploy', 1, '{"project": "payment-gateway", "version": "v2.14.3"}', '10.0.1.5', NOW() - INTERVAL '2 hours'),
    ('secret_rotated', 1, '{"secret": "jwt_signing_key"}', '10.0.1.5', NOW() - INTERVAL '7 days'),
    ('user_created', 1, '{"username": "raj.patel", "role": "developer"}', '10.0.1.5', NOW() - INTERVAL '14 days'),
    ('login_failed', NULL, '{"username": "test"}', '203.0.113.42', NOW() - INTERVAL '1 hour'),
    ('webhook_test', 2, '{"url": "https://hooks.slack.com/test"}', '10.0.1.12', NOW() - INTERVAL '4 hours');

-- ============================================================
-- Indexes for performance
-- ============================================================
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_projects_owner ON projects(owner_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_secrets_name ON secrets(secret_name);
