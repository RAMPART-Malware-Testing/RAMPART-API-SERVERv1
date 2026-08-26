CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users are authenticated exclusively via external OAuth providers (Google, GitHub).
-- There is no local password: identity is proven by the provider, this table only
-- stores the minimal profile data the app needs.
CREATE TABLE "users" (
    "uid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "avatar_url" TEXT DEFAULT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'active',
    "created_by" UUID REFERENCES "users"("uid"),
    "fcm_token" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
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
