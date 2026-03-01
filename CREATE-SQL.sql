-- 1. ตารางผู้ใช้งาน (Users)
CREATE TABLE "users" (
    "uid" SERIAL PRIMARY KEY,
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,
    "role" VARCHAR(20) DEFAULT 'user',
    "status" VARCHAR(50) DEFAULT 'ACTIVE',
    "created_by" INTEGER REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. ตารางการวิเคราะห์ (Analysis)
-- ปรับแก้: ลบการอ้างอิงถึง uploads/files ออก
CREATE TABLE "analysis" (
    "aid" SERIAL PRIMARY KEY,
    "uid" INTEGER NOT NULL,
    "task_id" TEXT,
    "privacy" BOOLEAN DEFAULT TRUE,
    "file_name" TEXT,
    "file_size" INTEGER,
    "file_hash" TEXT,
    "file_path" TEXT,
    "file_type" TEXT,
    "tools" TEXT,
    "md5" TEXT,
    "deleted_at" TIMESTAMPTZ,
    "deleted_by" INTEGER REFERENCES "users"("uid"),
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_analysis_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE
);

-- 3. ตารางรายงานผล (Reports)
-- เชื่อมโยง 1:1 หรือ 1:N กับ Analysis
CREATE TABLE "reports" (
    "rid" SERIAL PRIMARY KEY,
    "aid" INTEGER NOT NULL,
    "rampart_score" NUMERIC(5, 2),
    "package" TEXT,
    "type" VARCHAR(255),
    "score" NUMERIC(5, 2),
    "risk_level" VARCHAR(128),
    "recommendation" TEXT, 
    "analysis_summary" TEXT,
    "risk_indicators" TEXT[],
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_report_analysis FOREIGN KEY ("aid") REFERENCES "analysis" ("aid") ON DELETE CASCADE
);

-- 4. ตารางประวัติการใช้งาน (Audit Logs)
-- ปรับแก้: ลบฟิลด์ target_up_id (ที่เคยชี้ไป upload) ออก
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