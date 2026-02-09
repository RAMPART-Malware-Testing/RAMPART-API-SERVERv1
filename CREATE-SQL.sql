-- 1. สร้าง Table User (ต้องสร้างก่อน เพราะ Log และ Upload อ้างอิงถึง)
CREATE TABLE "users" (
    "uid" SERIAL PRIMARY KEY,              -- ใช้ SERIAL เพื่อ Auto Increment
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" TEXT NOT NULL,      -- เก็บ Hash Password
    "role" VARCHAR(20) DEFAULT 'user',     -- เช่น 'admin', 'user'
    "status" VARCHAR(50) DEFAULT 'ACTIVE' -- ACTIVE, BANNED
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP -- ใช้ TIMESTAMPTZ เพื่อรองรับ Timezone
);

-- 2. สร้าง Table File (ต้องสร้างก่อน เพราะ Upload และ Analysis อ้างอิงถึง)
CREATE TABLE "files" (
    "fid" SERIAL PRIMARY KEY,
    "file_hash" TEXT NOT NULL UNIQUE,
    "file_path" TEXT NOT NULL,              -- path ที่เก็บไฟล์จริง
    "file_type" TEXT,               -- MIME type เช่น application/pdf
    "file_size" BIGINT NOT NULL,             -- ขนาดไฟล์ (bytes)
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


-- 3. สร้าง Table Log (User 1 คน มีหลาย Log)
CREATE TABLE "logs" (
    "lid" SERIAL PRIMARY KEY,
    "uid" INTEGER NOT NULL,
    "message" TEXT,
    "success" BOOLEAN DEFAULT FALSE,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE
);

-- 4. สร้าง Table Upload (User 1 คน มีหลาย Upload, File 1 ไฟล์ ถูก Upload ได้หลายครั้ง)
CREATE TABLE "uploads" (
    "up_id" SERIAL PRIMARY KEY,
    "file_name" TEXT,
    "uid" INTEGER NOT NULL,
    "fid" INTEGER NOT NULL,
    "privacy" BOOLEAN DEFAULT TRUE,        -- True = Private, False = Public
    "uploaded_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_upload_user FOREIGN KEY ("uid") REFERENCES "users" ("uid") ON DELETE CASCADE,
    CONSTRAINT fk_upload_file FOREIGN KEY ("fid") REFERENCES "files" ("fid") ON DELETE RESTRICT
);

-- 5. สร้าง Table Analysis (File 1 ไฟล์ มี Analysis ได้ - เชื่อมโยงไปที่ File)
CREATE TABLE "analysis" (
    "aid" SERIAL PRIMARY KEY,
    "fid" INTEGER NOT NULL,
    "task_id" TEXT,
    "status" VARCHAR(50) DEFAULT 'pending', -- pending, processing, completed
    "platform" TEXT[],                      -- PostgreSQL รองรับ Array โดยใช้ []
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_analysis_file FOREIGN KEY ("fid") REFERENCES "files" ("fid") ON DELETE CASCADE
);

-- 6. สร้าง Table Report (Analysis 1 อัน มี Report ผลลัพธ์)
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
