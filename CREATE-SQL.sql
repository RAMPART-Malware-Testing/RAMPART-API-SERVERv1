
CREATE TABLE "users" (
    "uid" SERIAL PRIMARY KEY,
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'ACTIVE'
    "created_by" INTEGER REFERENCES users(uid)
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "audit_logs" (
    "log_id" SERIAL PRIMARY KEY,
    "actor_uid" INTEGER NOT NULL,
    "target_uid" INTEGER,
    "target_up_id" INTEGER,
    "action" VARCHAR(255),
    "detail" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_actor FOREIGN KEY ("actor_uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_log_target_user FOREIGN KEY ("target_uid") REFERENCES "users" ("uid") ON DELETE SET NULL,
    CONSTRAINT fk_log_target_upload FOREIGN KEY ("target_up_id") REFERENCES "uploads" ("up_id") ON DELETE SET NULL
);

CREATE TABLE "analysis" (
    "aid" SERIAL PRIMARY KEY,
    "uid" INTEGER NOT NULL,
    "privacy" BOOLEAN DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "md5" TEXT DEFAULT NULL,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" INTEGER REFERENCES users.uid
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_upload_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_upload_file FOREIGN KEY ("fid") REFERENCES "files" ("fid") ON DELETE RESTRICT
);

CREATE TABLE "analysis" (
    "task_id" TEXT,
    "status" VARCHAR(50) DEFAULT 'pending',
    "platform" TEXT DEFAULT "",
    "md5" TEXT DEFAULT NULL,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_analysis_file FOREIGN KEY ("fid") REFERENCES "files" ("fid") ON DELETE CASCADE
);

CREATE TABLE "reports" (
    "rid" SERIAL PRIMARY KEY,
    "aid" INTEGER UNIQUE NOT NULL,
    "rampart_score" NUMERIC(5, 2),
    "package" TEXT,
    "type" VARCHAR(255),
    "score" NUMERIC(5, 2),
    "risk_level" VARCHAR(128),
    "color" VARCHAR(128),
    "recommendation" TEXT, 
    "analysis_summary" TEXT,
    "risk_indicators" TEXT[],
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_report_analysis FOREIGN KEY ("aid") REFERENCES "analysis" ("aid") ON DELETE CASCADE
);
