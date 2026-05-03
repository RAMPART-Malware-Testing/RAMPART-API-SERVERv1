-- Active: 1777825765727@@127.0.0.1@5433@rampart
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

CREATE TABLE "reports" (
    "rid" SERIAL PRIMARY KEY,                               -- 1. รหัส Report (คงชื่อ rid ไว้เพื่อไม่ให้กระทบ Foreign Key ของตาราง analysis)
    "file_type" VARCHAR(50),                                -- 2. ชนิดของไฟล์ เช่น exe, apk, pdf
    "virustotal_score" INTEGER DEFAULT NULL,                -- 3. คะแนนจาก VirusTotal (แนะนำใช้ INTEGER เพราะมักจะเก็บเป็นจำนวนแอนตี้ไวรัสที่จับได้ เช่น 26)
    "mobsf_score" NUMERIC(5, 2) DEFAULT NULL,               -- 4. คะแนนจาก MobSF (มักเป็นทศนิยมตามมาตรฐาน CVSS)
    "cape_score" NUMERIC(5, 2) DEFAULT NULL,                -- 5. คะแนนจาก CAPE Sandbox (มักเป็นคะแนน 0.0 - 10.0)
    "rampart_score" NUMERIC(5, 2) DEFAULT NULL,             -- 6. คะแนนความน่าจะเป็นจาก Rampart AI
    "gemini_recommendation" TEXT DEFAULT NULL,              -- 7. คำแนะนำเชิงลึกจาก Gemini (กรณีทุกเครื่องมือผ่านหมด หรือต้องการบทสรุป)
    "malware_signatures" TEXT[] DEFAULT NULL,               -- (เพิ่มเติม) เก็บ Array ของชื่อตระกูลมัลแวร์ที่เราสกัดมา
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP      -- วันที่สร้าง Report
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