# SQL Architecture — ความสัมพันธ์ของตาราง (RAMPART API Server)

> แหล่งความจริง (source of truth) ของ schema คือ `cores/Schema/schema_class.py` — ตารางถูกสร้างอัตโนมัติตอน server start ผ่าน `init_db()`
> `CREATE-SQL.sql` เป็น mirror สำหรับ setup ฐานข้อมูลใหม่ด้วยมือ
> `cores/models_class.py` เป็น dead code (schema เก่าแบบ integer PK) ห้ามใช้อ้างอิง

## ภาพรวม

ทั้งหมด 7 ตาราง ใช้ UUID เป็น primary key (`gen_random_uuid()` จาก extension `pgcrypto`) โดยมี `users` เป็นศูนย์กลาง — ทุกตารางที่เหลือยกเว้น `reports` จะมี FK กลับมาที่ `users.uid`

| กลุ่ม | ตาราง | หน้าที่ |
|---|---|---|
| ตัวตน | `users`, `oauth_accounts` | บัญชีผู้ใช้ + แผนที่บัญชีกับ external identity (Google/GitHub) |
| งานวิเคราะห์ | `analysis`, `reports` | งานสแกนแต่ละชิ้น + ผลรวมคะแนนจากทุก tool |
| ประวัติ/ตรวจสอบย้อนหลัง | `audit_logs`, `login_history`, `download_history` | ใครทำอะไร, login เมื่อไร, ดาวน์โหลดอะไร |

## ER Diagram

```mermaid
erDiagram
    users {
        uuid uid PK
        varchar username UK
        varchar email UK
        text password "NULL = OAuth-only account"
        varchar role "user / admin / master"
        boolean is_banned "source of truth ของ access control"
        uuid created_by FK
        uuid banned_by FK
    }
    oauth_accounts {
        uuid id PK
        uuid uid FK
        varchar provider "google / github"
        varchar provider_uid "คู่กับ provider ต้อง unique"
        varchar provider_email
    }
    analysis {
        uuid aid PK
        uuid uid FK
        uuid rid FK "NULL ได้"
        text task_id "index แยกต่างหาก"
        text status
        timestamptz deleted_at "soft delete"
        uuid deleted_by FK
    }
    reports {
        uuid rid PK
        numeric rampart_score
        jsonb rampart_ai_score
    }
    audit_logs {
        uuid log_id PK
        uuid actor_uid FK
        uuid target_uid FK "NULL ได้"
        varchar action
    }
    login_history {
        uuid id PK
        uuid uid FK
        varchar provider "password / google / github"
        varchar status
    }
    download_history {
        uuid id PK
        uuid uid FK
        varchar tool
        varchar md5
    }

    users ||--o{ oauth_accounts : "uid"
    users ||--o{ analysis : "uid"
    reports |o--o{ analysis : "rid"
    users ||--o{ audit_logs : "actor_uid"
    users |o--o{ audit_logs : "target_uid"
    users ||--o{ login_history : "uid"
    users ||--o{ download_history : "uid"
    users ||--o{ users : "created_by / banned_by (self-reference)"
```

## สรุปความสัมพันธ์ทั้งหมด

| # | FK (คอลัมน์ → เป้าหมาย) | Cardinality | ON DELETE | ความหมาย |
|---|---|---|---|---|
| 1 | `oauth_accounts.uid → users.uid` | 1 user : 0..N identity | `CASCADE` | ลบ user = identity ทั้งหมดหายตาม |
| 2 | `analysis.uid → users.uid` | 1 user : 0..N analysis | `CASCADE` | ลบ user = งานวิเคราะห์ของเขาหายตาม |
| 3 | `analysis.rid → reports.rid` | 1 report : 0..N analysis | `SET NULL` | ลบ report ได้โดย analysis ยังอยู่ แค่ไม่มีผลรวมให้ดู |
| 4 | `analysis.deleted_by → users.uid` | — | *(NO ACTION)* | ห้ามลบ user ที่เป็นคน soft-delete งานไว้ จนกว่าจะเคลียร์คอลัมน์นี้ก่อน |
| 5 | `audit_logs.actor_uid → users.uid` | 1 user : 0..N log | `CASCADE` | ลบ user = log ที่เขาเป็นคนทำหายตาม |
| 6 | `audit_logs.target_uid → users.uid` | 1 user : 0..N log | `SET NULL` | ลบ user = log ที่เขาเป็น "เป้า" ยังอยู่ แต่ไม่รู้ว่าเป้าคือใคร |
| 7 | `login_history.uid → users.uid` | 1 user : 0..N row | `CASCADE` | ประวัติ login ตาม user |
| 8 | `download_history.uid → users.uid` | 1 user : 0..N row | `CASCADE` | ประวัติดาวน์โหลดตาม user |
| 9 | `users.created_by → users.uid` | self-ref | *(NO ACTION)* | ใครสร้างบัญชีนี้ (admin สร้างให้) — ข้อมูลอ้างอิงเท่านั้น |
| 10 | `users.banned_by → users.uid` | self-ref | *(NO ACTION)* | ใครเป็นคนสั่งแบน |

ข้อสังเกต: คอลัมน์ที่ "จำคนทำ" ไว้เป็นหลักฐาน (`created_by`, `banned_by`, `deleted_by`) ตั้งใจไม่ใส่ `ON DELETE` — ปล่อยให้เป็น `NO ACTION` เพื่อกันลบ user ทิ้งแล้วหลักฐานเชื่อมโยงหาย ส่วนข้อมูลที่เป็นของ user (`oauth_accounts`, `analysis`, log ต่าง ๆ) ใช้ `CASCADE` ให้ลบสะอาดในครั้งเดียว

## รายละเอียดแต่ละตาราง

### `users`
บัญชีผู้ใช้เดียวของระบบ รับทั้งสองช่องทาง auth:
- **Local** — email + password (Argon2) + OTP → `password` มีค่า hash
- **OAuth** — Google/GitHub → `password` เป็น NULL

คอลัมน์สำคัญ:
- `email` / `username` — unique ทั้งคู่, email คือ canonical identity ที่ใช้เชื่อมบัญชีข้าม provider
- `role` — `user` / `admin` / `master` (`master` ได้มาจาก `ROOT_EMAIL` ตอน OAuth login เท่านั้น ห้ามผ่าน API/UI)
- `is_banned` (+ `banned_at`, `banned_reason`, `banned_by`) — **source of truth** ของ access control; `status` เป็น legacy flag ที่ไม่ authoritative แล้ว
- `fcm_token` — push notification

### `oauth_accounts`
แผนที่ "user คนนี้เชื่อมกับใครในโลกภายนอกบ้าง" — 1 user ผูกได้หลาย identity

- ค้นหา repeat login ด้วยคู่ `(provider, provider_uid)` — คู่นี้เท่านั้นที่ provider รับประกันว่า stable และ unique (`UNIQUE` constraint)
- ถ้ามาจาก provider ใหม่แต่ email ตรงกับ user เดิม (และ provider ยืนยัน email แล้ว) → เพิ่มแถวใหม่ชี้ไปที่ uid เดิม ไม่สร้างบัญชีซ้ำ (ดู `find_or_create_user` ใน `services/oauth/oauth_service.py`)
- `provider_email` แยกจาก `users.email` ตั้งใจ — email ที่ provider คืนมา (เช่น noreply ของ GitHub) ไม่จำเป็นต้องตรงกับ email หลักของบัญชี

**ทำไมไม่รวมเป็นตารางเดียวกับ `users`?** เพราะความสัมพันธ์เป็น 1:N (คนหนึ่ง login ได้หลาย provider) และมี user ที่ไม่มี OAuth เลย (local password) — ถ้ายุบเป็นคอลัมน์ `provider`/`provider_uid` บน `users` จะเก็บ identity ได้แถวละตัวเดียว ทำ linking ข้าม provider ไม่ได้ และ user แบบ password จะมีคอลัมน์เหล่านั้นเป็น NULL ตลอดชีวิต นี่คือ pattern มาตรฐานเดียวกับตาราง `accounts` ของ NextAuth / `identities` ของ Supabase

### `analysis`
งานสแกนหนึ่งชิ้นต่อหนึ่งแถว — สร้างที่ขั้น upload (status `pending`) แล้วถูก Celery task อัปเดตตลอด pipeline (VirusTotal → MobSF → CAPE → RampartAI → Gemini)

- `task_id` — Celery task ที่รันงานนี้; หลายแถว (คนละ user) อาจแชร์ `task_id` เดียวกันเพราะ dedup ด้วย file hash
- `status` — `pending` → ... → `success` / `failed` / skipped states ต่าง ๆ
- `is_malicious`, `blocked_by` — ถ้า VirusTotalตัดสินว่าเป็น malware งานถูก block ทันที
- `deleted_at` / `deleted_by` — soft delete (แถวไม่หาย แค่ซ่อน); partial unique index ด้านล่างทำงานคู่กับคอลัมน์นี้
- `privacy` — สวิตช์ส่วนตัว/สาธารณะของงาน

### `reports`
ผลรวมคะแนนจากทุก tool ของ pipeline หนึ่งรอบ (`virustotal_score`, `mobsf_score`, `cape_score`, `rampart_ai_score` JSONB, `gemini_recommendation`, `malware_signatures` ฯลฯ)

- **ไม่มีคอลัมน์ `uid` ตั้งใจ** — เพราะงานที่ dedup แล้ว (คนละ user อัปโหลดไฟล์เดียวกัน) รัน pipeline ร่วมกันและได้ report แถวเดียวร่วมกัน (ดู `bgProcessing/tasks.py` ตอน finalize: ทุก analysis ใน `task_id` เดียวต้องชี้ `rid` เดียวกัน)
- `ON DELETE SET NULL` ที่ `analysis.rid` ทำให้ลบ report เก่าทิ้งได้โดย history ของ analysis ยังอยู่ครบ

### `audit_logs`
บันทึกการกระทำสำคัญเพื่อตรวจสอบย้อนหลัง (ส่วนใหญ่คือ admin action) — มีสองมุมมอง: `actor_uid` คือคนทำ, `target_uid` คือคนถูกกระทำ (nullable เพราะบาง action ไม่มีเป้าหมายเป็น user)

### `login_history`
แถวต่อความพยายาม login หนึ่งครั้ง (ทั้งสำเร็จและล้มเหลว, ทั้ง password และ OAuth) — `provider` บอกช่องทาง, `ip` / `user_agent` บอกที่มา

### `download_history`
แถวต่อการดาวน์โหลดรายงานหนึ่งครั้ง (ดู `controller/analysis_controller.py::downloadReport_controller`) — `md5` ระบุไฟล์ที่โหลด, `tool` ระบุรายงานของ tool ไหน

## เส้นทางข้อมูลหลัก

```text
สมัคร/ล็อกอิน
  local:     users (password = Argon2 hash) ──→ login_history
  OAuth:     users + oauth_accounts (ผูก identity) ──→ login_history

อัปโหลดไฟล์วิเคราะห์
  analysis (uid, task_id, status=pending, file hashes)
      │  dedup: ไฟล์เดียวกัน (sha256) จากหลาย user
      │  = analysis หลายแถว + task_id เดียว
      ▼
  Celery pipeline (VirusTotal → MobSF → CAPE → RampartAI → Gemini)
      │  ตอน finalize
      ▼
  reports (ผลรวมคะแนน) ←── analysis.rid (ทุกแถวใน task เดียวชี้ report เดียว)

ฝั่ง admin
  ban user → users.is_banned* → audit_logs (actor + target)
  ลบงาน    → analysis.deleted_at/deleted_by (soft delete) → audit_logs
```

## Indexes

| ตาราง | Index | ไว้ทำอะไร |
|---|---|---|
| `users` | `UNIQUE(username)`, `UNIQUE(email)` | กันซ้ำ + lookup ตอน login |
| `oauth_accounts` | `UNIQUE(provider, provider_uid)` | resolve repeat login ให้ uid เดิมเสมอ |
| `oauth_accounts` | `ix_oauth_accounts_uid(uid)` | หา identity ทั้งหมดของ user |
| `analysis` | `uq_analysis_task_uid_active(task_id, uid) WHERE deleted_at IS NULL` | กันงานซ้ำที่ยังไม่ถูก soft-delete ของ user เดียวกัน (partial unique index — มีเฉพาะใน `schema_class.py` ดูหมายเหตุด้านล่าง) |
| `analysis` | `ix_analysis_file_hash(file_hash)` | ค้นหา/dedup ด้วย hash |
| `analysis` | `ix_analysis_task_id(task_id)` | หาทุก analysis ของ task เดียว (ตอน finalize) |
| `analysis` | `ix_analysis_uid_created_at(uid, created_at DESC)` | ประวัติงานล่าสุดของ user (หน้า dashboard/history) |

## หมายเหตุและกฎการดูแล

- **Partial unique index ต่างกันระหว่างสองแหล่ง** — `uq_analysis_task_uid_active` มีใน `schema_class.py` (`__table_args__`) แต่ไม่มีใน `CREATE-SQL.sql` ถ้าสร้างฐานข้อมูลจาก `CREATE-SQL.sql` ล้วน ๆ ต้องเพิ่มเอง:
  ```sql
  CREATE UNIQUE INDEX uq_analysis_task_uid_active
      ON analysis (task_id, uid)
      WHERE deleted_at IS NULL;
  ```
- ตาม AGENTS.md — `Base.metadata.create_all` **สร้างเฉพาะตารางที่ยังไม่มี** ไม่เคย `ALTER TABLE` ให้ การเพิ่มคอลัมน์ใหม่บนตารางที่มีอยู่ต้องรัน ALTER กับ Postgres container (port 5433) ด้วยมือ และ mirror กลับใน `CREATE-SQL.sql` ทุกครั้ง
- Database จริงคือ Postgres container พอร์ต **5433** (ไม่ใช่ 5432) — `cores/async_pg_db.py` (FastAPI) และ `cores/sync_pg_db.py` (Celery) ชี้มาที่เดียวกัน
