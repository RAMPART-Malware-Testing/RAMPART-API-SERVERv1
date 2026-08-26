CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users can authenticate either via a local email+password (with OTP
-- confirmation) OR via an external OAuth provider (Google, GitHub) - both
-- flows coexist and resolve to the same "users" row. "password" is NULL for
-- OAuth-only accounts (that never called /api/auth/register); AuthService.login
-- rejects login for any account whose password is NULL rather than crashing.
CREATE TABLE "users" (
    "uid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NULL, -- Argon2 hash (utils/cypto/PasswordCreateAndVerify.py). NULL for OAuth-only accounts.
    "avatar_url" TEXT DEFAULT NULL,
    "role" VARCHAR(20) DEFAULT 'user', -- 'user' | 'admin' | 'master'. 'master' can ONLY be assigned by the ROOT_EMAIL OAuth login branch, never via API/UI.
    "status" VARCHAR(50) DEFAULT 'active', -- legacy free-text flag, NOT authoritative for access control anymore, see is_banned
    "created_by" UUID REFERENCES "users"("uid"),
    "fcm_token" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    -- Ban state: source of truth for access control. Master accounts can never
    -- be banned (enforced at the service layer, not a DB constraint).
    "is_banned" BOOLEAN NOT NULL DEFAULT FALSE,
    "banned_at" TIMESTAMPTZ NULL,
    "banned_reason" TEXT NULL,
    "banned_by" UUID NULL REFERENCES "users"("uid")
);

-- Links one user to one or more external OAuth identities (Google / GitHub).
-- Looking a row up by (provider, provider_uid) is how a repeat login resolves
-- back to the same "uid" every time. If a person signs in with a different
-- provider using the same verified e-mail address, a second row is linked to
-- the same user instead of creating a duplicate account.
CREATE TABLE "oauth_accounts" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "provider" VARCHAR(20) NOT NULL,
    "provider_uid" VARCHAR(255) NOT NULL,
    "provider_email" VARCHAR(255),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("provider", "provider_uid")
);

CREATE INDEX "ix_oauth_accounts_uid" ON "oauth_accounts"("uid");

CREATE TABLE "reports" (
    "rid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "rampart_score" NUMERIC(5, 2),
    "package" TEXT,
    "type" VARCHAR(255),
    "score" NUMERIC(5, 2),
    "risk_level" VARCHAR(128),
    "recommendation" TEXT,
    "analysis_summary" TEXT,
    "risk_indicators" TEXT[],
    "file_type" VARCHAR(50),
    "virustotal_score" INTEGER,
    "mobsf_score" NUMERIC(5, 2),
    "cape_score" NUMERIC(5, 2),
    "rampart_ai_score" JSONB,
    "gemini_recommendation" TEXT,
    "malware_signatures" TEXT[],
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "audit_logs" (
    "log_id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "actor_uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "target_uid" UUID REFERENCES "users"("uid") ON DELETE SET NULL,
    "action" VARCHAR(255),
    "detail" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- One row per successful/failed login attempt (both password and OAuth flows).
CREATE TABLE "login_history" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "provider" VARCHAR(32), -- 'password' | 'google' | 'github'
    "ip" VARCHAR(64),
    "user_agent" TEXT,
    "status" VARCHAR(32),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- One row per raw-report download (see controller/analysis_controller.py::downloadReport_controller).
CREATE TABLE "download_history" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "file_name" TEXT,
    "tool" VARCHAR(32),
    "md5" VARCHAR(32),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "analysis" (
    "aid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "rid" UUID REFERENCES "reports"("rid") ON DELETE SET NULL,
    "task_id" TEXT,
    "privacy" BOOLEAN DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "tools" TEXT,
    "tool_notes" TEXT,
    "status" TEXT DEFAULT 'pending',
    "blocked_by" VARCHAR(50),
    "is_malicious" BOOLEAN DEFAULT FALSE,
    "md5" TEXT,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" UUID REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "ix_analysis_file_hash" ON "analysis"("file_hash");
CREATE INDEX "ix_analysis_task_id" ON "analysis"("task_id");
CREATE INDEX "ix_analysis_uid_created_at" ON "analysis"("uid", "created_at" DESC);
