CREATE TABLE "users" (
    "uid" SERIAL PRIMARY KEY,
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'active',
    "created_by" INTEGER REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "analysis" (
    "aid" SERIAL PRIMARY KEY,
    "uid" INTEGER NOT NULL,
    "rid" INTEGER DEFAULT NULL,
    "task_id" TEXT,
    "privacy" BOOLEAN DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "tools" TEXT,
    "status" TEXT DEFAULT 'pending',
    "md5" TEXT,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" INTEGER REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_analysis_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_analysis_report FOREIGN KEY ("rid") REFERENCES "reports" ("rid") ON DELETE SET NULL
);

CREATE TABLE "reports" (
    "rid" SERIAL PRIMARY KEY,
    "rampart_score" NUMERIC(5, 2),
    "package" TEXT,
    "type" VARCHAR(255),
    "score" NUMERIC(5, 2),
    "risk_level" VARCHAR(128),
    "recommendation" TEXT, 
    "analysis_summary" TEXT,
    "risk_indicators" TEXT[],
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "audit_logs" (
    "log_id" SERIAL PRIMARY KEY,
    "actor_uid" INTEGER NOT NULL,
    "target_uid" INTEGER,
    "action" VARCHAR(255),
    "detail" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_actor FOREIGN KEY ("actor_uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_log_target_user FOREIGN KEY ("target_uid") REFERENCES "users" ("uid") ON DELETE SET NULL
);