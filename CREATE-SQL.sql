CREATE TABLE "users" (
    "uid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'active',
    "created_by" UUID REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "reports" (
    "rid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "file_type" VARCHAR(50),
    "virustotal_score" INTEGER DEFAULT NULL,
    "mobsf_score" NUMERIC(5, 2) DEFAULT NULL,
    "cape_score" NUMERIC(5, 2) DEFAULT NULL,
    "rampart_score" NUMERIC(5, 2) DEFAULT NULL,
    "gemini_recommendation" TEXT DEFAULT NULL,
    "malware_signatures" TEXT[] DEFAULT NULL,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "audit_logs" (
    "log_id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "actor_uid" UUID NOT NULL,
    "target_uid" UUID,
    "action" VARCHAR(255),
    "detail" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_actor FOREIGN KEY ("actor_uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_log_target_user FOREIGN KEY ("target_uid") REFERENCES "users" ("uid") ON DELETE SET NULL
);

CREATE TABLE "analysis" (
    "aid" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "uid" UUID NOT NULL,
    "rid" UUID DEFAULT NULL,
    "task_id" TEXT,
    "privacy" BOOLEAN DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "tools" TEXT,
    "status" TEXT DEFAULT 'pending',
    "blocked_by" VARCHAR(50) DEFAULT NULL,
    "is_malicious" BOOLEAN DEFAULT FALSE,
    "md5" TEXT,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" UUID REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_analysis_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_analysis_report FOREIGN KEY ("rid") REFERENCES "reports" ("rid") ON DELETE SET NULL
);