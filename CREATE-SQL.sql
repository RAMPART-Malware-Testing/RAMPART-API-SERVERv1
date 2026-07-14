CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE "users" (
    "uid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'active',
    "created_by" UUID REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    "fcm_token" TEXT
);

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
