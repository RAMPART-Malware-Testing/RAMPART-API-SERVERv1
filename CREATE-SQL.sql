CREATE TABLE "users" (
    "uid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NULL,
    "avatar_url" TEXT DEFAULT NULL,
    "role" VARCHAR(20) NOT NULL DEFAULT 'user',
    "status" VARCHAR(50) NOT NULL DEFAULT 'active',
    "created_by" UUID REFERENCES "users"("uid"),
    "fcm_token" TEXT,
    "is_banned" BOOLEAN NOT NULL DEFAULT FALSE,
    "banned_at" TIMESTAMPTZ NULL,
    "banned_reason" TEXT NULL,
    "banned_by" UUID NULL REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "oauth_accounts" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "provider" VARCHAR(20) NOT NULL,
    "provider_uid" VARCHAR(255) NOT NULL,
    "provider_email" VARCHAR(255),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "uq_oauth_accounts_provider_identity" UNIQUE ("provider", "provider_uid")
);

CREATE INDEX "ix_oauth_accounts_uid" ON "oauth_accounts"("uid");

CREATE TABLE "reports" (
    "rid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "package" TEXT,
    "type" VARCHAR(255),
    "score" NUMERIC(5, 2),
    "score_source" VARCHAR(20),
    "risk_level" VARCHAR(128),
    "recommendation" TEXT,
    "analysis_summary" TEXT,
    "risk_indicators" TEXT[],
    "detected_type" VARCHAR(50),
    "file_type" VARCHAR(50),
    "virustotal_score" INTEGER,
    "mobsf_score" NUMERIC(5, 2),
    "cape_score" NUMERIC(5, 2),
    "rampart_ai_score" JSONB,
    "rampart_score" NUMERIC(5, 2),
    "gemini_recommendation" TEXT,
    "malware_signatures" TEXT[],
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "audit_logs" (
    "log_id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "actor_uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "target_uid" UUID REFERENCES "users"("uid") ON DELETE SET NULL,
    "action" VARCHAR(255),
    "detail" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "login_history" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "provider" VARCHAR(32),
    "ip" VARCHAR(64),
    "user_agent" TEXT,
    "status" VARCHAR(32),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "download_history" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "file_name" TEXT,
    "tool" VARCHAR(32),
    "md5" VARCHAR(32),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "analysis" (
    "aid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL REFERENCES "users"("uid") ON DELETE CASCADE,
    "rid" UUID REFERENCES "reports"("rid") ON DELETE SET NULL,
    "task_id" TEXT,
    "privacy" BOOLEAN NOT NULL DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "detected_type" VARCHAR(50),
    "detected_source" VARCHAR(20),
    "file_type_mismatch" BOOLEAN NOT NULL DEFAULT FALSE,
    "tools" TEXT,
    "tool_notes" TEXT,
    "tool_states" JSONB,
    "status" TEXT DEFAULT 'pending',
    "blocked_by" VARCHAR(50),
    "is_malicious" BOOLEAN DEFAULT FALSE,
    "md5" TEXT,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" UUID REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "ix_analysis_created_at" ON "analysis"("created_at" DESC);
CREATE INDEX "ix_analysis_detected_type" ON "analysis"("detected_type");
CREATE INDEX "ix_analysis_file_hash" ON "analysis"("file_hash");
CREATE INDEX "ix_analysis_md5" ON "analysis"("md5");
CREATE INDEX "ix_analysis_task_id" ON "analysis"("task_id");
CREATE INDEX "ix_analysis_uid_created_at" ON "analysis"("uid", "created_at" DESC);
CREATE UNIQUE INDEX "uq_analysis_task_uid_active" ON "analysis"("task_id", "uid") WHERE "deleted_at" IS NULL;

CREATE INDEX "ix_audit_logs_actor_uid_created_at" ON "audit_logs"("actor_uid", "created_at" DESC);
CREATE INDEX "ix_audit_logs_created_at" ON "audit_logs"("created_at" DESC);
CREATE INDEX "ix_download_history_uid_created_at" ON "download_history"("uid", "created_at" DESC);
CREATE INDEX "ix_login_history_uid_created_at" ON "login_history"("uid", "created_at" DESC);
