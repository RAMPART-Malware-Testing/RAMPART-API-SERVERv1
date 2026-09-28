# การออกแบบระบบวิเคราะห์ไฟล์ซ้ำ (Analysis Dedup & Reuse)

เอกสารนี้อธิบายสาเหตุที่ระบบปัจจุบันสร้าง `analysis` และ `reports` ซ้ำเมื่ออัปโหลดไฟล์เดิม
และออกแบบระบบใหม่ให้เป็นไปตามเป้าหมาย 4 ข้อของผู้ใช้งาน

โค้ดที่เกี่ยวข้อง:
- `controller/Analysis/ScanFile_controller.py` — เส้นทางอัปโหลดไฟล์เต็ม
- `controller/Analysis/CheckHash_controller.py` — เส้นทางตรวจ hash ก่อนอัปโหลด
- `services/analy/analy_service.py` — logic dedup ทั้งหมด (get_file_by_hash / attach / gap-fill / insert)
- `bgProcessing/tasks.py` — pipeline วิเคราะห์ (`analyze_malware_task`, `finalize_analysis_report`)
- `bgProcessing/task_handlers.py` — handler ของแต่ละ tool (คืนสถานะ success / pending / skipped / failed)
- `cores/Schema/schema_class.py` — ตาราง `analysis`, `reports`
- `CREATE-SQL.sql` — schema ที่ใช้จริงบน Postgres

---

## 1. สรุปผู้บริหาร

| หัวข้อ | สรุป |
|---|---|
| อาการ | ผู้ใช้คนเดิมอัปโหลดไฟล์เดิมซ้ำ → เกิด `analysis` แถวใหม่ และ `reports` แถวใหม่ทุกครั้ง |
| สาเหตุหลัก | gap-fill (`attempt_gap_fill_redispatch`) สร้าง task ใหม่ + แถวใหม่ + report ใหม่เสมอ และถูกกระตุ้นซ้ำทุกครั้งที่อัปโหลด ตราบใดที่แถวล่าสุดยังมี `tool_notes` |
| สาเหตุรอง | key ของ dedup ฝั่งผู้ใช้ผูกกับ `file_name` (ไม่ใช่ตัวไฟล์), ตัวตัดสิน "ต้องวิเคราะห์ซ้ำไหม" ใช้ข้อความ `tool_notes` แทนการตรวจความครบถ้วนจริง, unique index กันแถวซ้ำไม่ถูกสร้างบน DB จริง |
| แนวทางแก้ | แยก "ตัวตนของไฟล์" (sha256 → 1 report) ออกจาก "มุมมองของผู้ใช้" (uid + sha256 → 1 แถว) แล้วให้ resolver ตัวเดียวตัดสิน reuse / รอ / re-run เฉพาะ tool ที่ขาด |
| ผลลัพธ์ | ไฟล์เดียวกัน = report เดียว, ผู้ใช้คนเดิม = analysis เดียว, ผู้ใช้ใหม่ = แถวใหม่ที่แชร์ report/task เดิม, tool ที่ล่มถูกวิเคราะห์ซ้ำเฉพาะตัวที่ขาด |

---

## 2. สถานะปัจจุบัน (As-Is)

### 2.1 เส้นทางอัปโหลด

```
POST /api/analy/v1/upload
  └─ require_upload_token → uid
  └─ scan_file_controller (ScanFile_controller.py:49)
       1. รับไฟล์เป็น chunk → md5 + sha256 (ห้ามเกิน 1 GB)
       2. attempt_gap_fill_redispatch()      ← ตรวจ "ต้องวิเคราะห์ซ่อมไหม" ก่อน
       3. acquire_analysis_hash_lock(sha256) ← advisory lock ต่อ hash
       4. get_file_by_hash(sha256)           ← แถวล่าสุดของ hash นี้
       5. ถ้าสถานะ dispatching → 409 ให้ลองใหม่
       6. ถ้าสถานะอยู่ใน {queued, processing, analyzing, success} → attach
            → insert_table_analy(uid, rid, task_id, tools, status, ...) แล้วคืน "reused"
       7. ถ้าไม่มีอะไร reuse ได้ → dispatch task ใหม่ → คืน "dispatched"
```

เส้นทาง `POST /api/analy/v1/check-hash` ทำแบบเดียวกันแต่ไม่ต้องอัปโหลดไบต์
(`CheckHash_controller.py:49-65` เรียก gap-fill ก่อน แล้วจึง attach)

### 2.2 พฤติกรรมจริงเทียบเป้าหมาย

| # | สถานการณ์ | พฤติกรรมปัจจุบัน | เป้าหมาย | ผล |
|---|---|---|---|---|
| S1 | ผู้ใช้คนเดิม อัปโหลดไฟล์เดิม ชื่อเดิม, วิเคราะห์ครบแล้ว | `insert_table_analy` เจอแถวเดิม (uid+file_name+hash) → UPDATE แถวเดิม | G1 | ผ่าน |
| S2 | ผู้ใช้คนเดิม ไฟล์เดิม แต่เปลี่ยนชื่อไฟล์ | attach → `insert_table_analy` ไม่เจอ (ชื่อไม่ตรง) → INSERT แถวที่สอง ที่มี `(task_id, uid)` เดิม | G1 | **พัง** |
| S3 | ผู้ใช้คนเดิม ไฟล์เดิม ที่รอบก่อนมี tool ล่ม (มี `tool_notes`) | gap-fill → task ใหม่ + แถวใหม่ + report ใหม่ | G1, G3 | **พัง** |
| S4 | ผู้ใช้ใหม่ ไฟล์ที่วิเคราะห์ครบแล้ว | attach → แถวใหม่ แชร์ task_id + rid เดิม | G2, G3 | ผ่าน |
| S5 | ผู้ใช้ใหม่ ไฟล์ที่กำลังวิเคราะห์อยู่ (ยังไม่มี rid) | attach → แถวใหม่ แชร์ task_id → รอผลรอบเดียวกัน | G2 | ผ่าน |
| S6 | ผู้ใช้ใหม่ ไฟล์ที่วิเคราะห์แล้วแต่ไม่ครบ | gap-fill → task ใหม่ + แถวใหม่ + report ใหม่ | G2, G3, G4 | **พัง** |
| S7 | ไฟล์เดิม ที่รอบก่อน `failed` | dispatch ใหม่ | G4 (ใกล้เคียง) | ผ่าน |
| S8 | ไฟล์ที่ VT ตรวจแล้วพบมัลแวร์ (score 100 → ข้าม MobSF/CAPE โดยเจตนา) | `tool_notes` มีค่า → gap-fill กระตุ้น → วิเคราะห์ MobSF/CAPE/RampartAI ซ้ำทั้งชุด | ต้องถือว่า "จบสมบูรณ์" | **พัง** |
| S9 | ไฟล์ success แต่ไฟล์ report บนดิสก์หาย | attach คืน rid เดิม → ดาวน์โหลด report แล้ว 404 | G4: ต้องวิเคราะห์ tool นั้นซ้ำ | **พัง** |
| S10 | ไฟล์ที่ tool ล่มซ้ำ ๆ ถูกอัปโหลดซ้ำหลายครั้ง | ทุกครั้งที่อัปโหลด = analysis + report ชุดใหม่ (ไม่จำกัดจำนวน) | ต้องมีขอบเขต | **พัง** |

---

## 3. สาเหตุราก (Root Causes)

### RC-1 — gap-fill สร้างของใหม่เสมอ และยิงซ้ำทุกครั้งที่อัปโหลด

- `analy_service.py:214-231` — `attempt_gap_fill_redispatch` สร้าง `task_id` ใหม่ (`uuid4()`),
  `session.add(Analysis(...))` โดย **ไม่ส่ง `rid` ต่อ** → เกิดแถวใหม่
- `tasks.py:242-261` — `finalize_analysis_report` เห็นว่าแถวของ task ใหม่มี `rid` เป็น `None`
  → สร้าง `Reports` แถวใหม่
- `analy_service.py:190` — เงื่อนไขกระตุ้นคือ `existing_status == "success" and tool_notes`
  → ตราบใดที่แถวล่าสุดยังมี `tool_notes` อยู่ การอัปโหลดครั้งถัดไปจะ gap-fill อีก
- ผลคือ S3, S6, S10: ทุกการอัปโหลด = 1 analysis ใหม่ + 1 report ใหม่ ไม่มีที่สิ้นสุด

### RC-2 — key ของ dedup ฝั่งผู้ใช้ผูกกับชื่อไฟล์ + unique index ไม่มีจริงบน DB

- `analy_service.py:304-311` — `insert_table_analy` มองหาแถวเดิมด้วย
  `(uid, file_name, file_hash)` → ไฟล์เดียวกันแต่ชื่อต่าง = มองไม่เห็นกัน → INSERT
- `schema_class.py:67-75` — model ประกาศ unique index `uq_analysis_task_uid_active (task_id, uid)`
  แต่ `CREATE-SQL.sql:117-119` ไม่มี index นี้ และ `Base.metadata.create_all` ไม่เพิ่ม index
  ให้ตารางที่มีอยู่แล้ว → บน DB จริงมีสองกรณี:
  - ถ้า index ถูกสร้างไว้แล้ว → INSERT แถวที่สองของ `(task_id, uid)` ล้มเหลว → HTTP 500
  - ถ้าไม่มี index → INSERT สำเร็จ → **แถวซ้ำเงียบ ๆ** (ตรงกับอาการที่รายงาน)

### RC-3 — ตัวตัดสิน "ต้องวิเคราะห์ซ่อมไหม" คือข้อความ `tool_notes` ไม่ใช่สถานะของ tool

`tool_notes` ถูกเขียนทั้งในกรณี "ข้ามโดยเจตนา" และ "ล่มจริง" ปนกัน:

| กรณี | เขียน note? | ตัวอย่างข้อความ | ควรถือเป็น |
|---|---|---|---|
| VT = 100 → ข้าม MobSF/CAPE/RampartAI | ใช่ (`tasks.py:428-431`) | `Skipped: VirusTotal already detected malware` | จบสมบูรณ์ (terminal) |
| MobSF: นามสกุลไม่รองรับ | ไม่ (`task_handlers.py:196-201`) | — | จบสมบูรณ์ (terminal) |
| CAPE: นามสกุลไม่รองรับ | ไม่ (`task_handlers.py:393`) | — | จบสมบูรณ์ (terminal) |
| VT: ไฟล์ใหญ่เกิน 32 MB | ไม่ (`task_handlers.py:81-86`) | — | จบสมบูรณ์ (terminal) |
| tool ใช้ retry จนหมดโควตา | ใช่ (`tasks.py:168,180`) | `MobSF skipped after 120 status checks...` | ต้องวิเคราะห์ซ้ำ (gap) |
| ไฟล์ report หายจากดิสก์ | ไม่ | — | ต้องวิเคราะห์ซ้ำ (gap) |

ผลคือตัดสินผิดทั้งสองทาง: S8 ยิงวิเคราะห์ซ้ำทั้งชุด และเคส terminal ที่ไม่มี note จะถูก
มองข้าม/สับสนได้ง่าย

### RC-4 — ไม่ตรวจความครบถ้วนจากหลักฐานจริง (ไฟล์ report)

`tools` column ถูกใช้เป็นหลักฐานว่า tool สำเร็จ แต่ไม่มีการตรวจว่าไฟล์
`reports/{tool}-{md5}.json` ยังอยู่จริง → S9 คืนสถานะ success ทั้งที่ปลายทางโหลดไม่ได้
(`analysis_controller.py:308-317` คืน `REPORT_FILE_NOT_FOUND`)

### RC-5 — เลือกผู้ให้ยืม (donor) จากแถวล่าสุดแถวเดียว

`analy_service.py:90` — `order_by(desc(created_at)).limit(1)`
ถ้าแถวล่าสุดของ hash กำลังวิเคราะห์อยู่ (`queued`) ขณะที่แถวก่อนหน้าเป็น success ที่ครบถ้วนแล้ว
ผู้ใช้ใหม่จะถูก attach เข้ากับงานที่ยังไม่เสร็จ แทนที่จะได้ report ที่เสร็จแล้วทันที

### RC-6 — `rampart_ai` ไม่อยู่ในรายการ tool ที่ส่งต่อผลสำเร็จ

`analy_service.py:19-23` — `_GAP_FILL_TOOL_KWARGS` มีแค่ virustotal/mobsf/cape
→ รอบซ่อมจะเรียก RampartAI ซ้ำเสมอ แม้ไฟล์ `reports/rampartai-{md5}.json` จะมีอยู่แล้ว

---

## 4. การออกแบบ (To-Be)

### 4.1 โมเดลตัวตน (Identity Model) — หัวใจของการออกแบบ

| สิ่ง | ตัวตน | จำนวนต่อไฟล์ |
|---|---|---|
| เนื้อหาไฟล์ | `analysis.file_hash` (sha256) | 1 |
| Report | `reports.rid` — **ผูกกับเนื้อหา ไม่ผูกกับผู้ใช้** | 1 |
| Run (Celery task) | `analysis.task_id` — 1 run ต่อการวิเคราะห์ 1 รอบ | 1..n (มีรอบซ่อมได้) |
| แถวของผู้ใช้ | `(uid, file_hash)` ที่ยังไม่ถูกลบ | 1 ต่อผู้ใช้ต่อไฟล์ |

**Invariants ที่ระบบต้องรักษา:**

| # | ข้อกำหนด | เป้าหมาย |
|---|---|---|
| R1 | ผู้ใช้ 1 คน มีแถวที่มีชีวิตอยู่ได้ไม่เกิน 1 แถวต่อ 1 เนื้อหาไฟล์ (ไม่นับชื่อไฟล์) | G1 |
| R2 | ทุกแถวของเนื้อหาเดียวกันชี้ไปที่ `rid` เดียวกัน | G3 |
| R3 | Run ใหม่ของเนื้อหาเดิม **ห้ามสร้าง report ใหม่** — finalize ต้องเขียนทับ report เดิม | G3 |
| R4 | `task_id` คือ handle ที่ฝ่าย client ใช้ poll: แถวของผู้ใช้ชี้ไปที่ run ที่รับผิดชอบสถานะปัจจุบันของเนื้อหานั้น (ถ้าต้องซ่อม จะ re-point แถวเดิมไป run ใหม่ — ไม่สร้างแถวใหม่) | G1, G4 |
| R5 | ทุกแถวที่ผูกกับ run หนึ่ง ต้องมี `rid` ค่าเดียวกัน (หรือ `None` ทั้งหมด) — เพราะ `finalize_analysis_report` ปฏิเสธกรณี rid ปนกัน (`tasks.py:217-219`) | ความถูกต้อง |
| R6 | ทุกการค้นหาเพื่อ reuse/แสดงผลต้องกรอง `deleted_at IS NULL` — แถวที่ถูกลบแบบ soft delete ยังมี `status='success'` และ `rid` เดิมอยู่ ถ้าไม่กรอง การอัปโหลดไฟล์ที่ถูกลบไปแล้วจะ attach กับ task_id ที่ endpoint ดูรายงานปฏิเสธที่จะแสดง → ผู้ใช้เห็น `TASK_NOT_FOUND` ทันทีหลังอัปโหลด | ความถูกต้อง |

> หมายเหตุ R3: กลไกนี้ทำงานได้ทันทีโดยไม่ต้องแก้ `finalize_analysis_report`
> เพราะโค้ดปัจจุบันตรวจ `report_ids = {row.rid}` — ถ้าทุกแถวของ run มี rid เดียวกัน
> มันจะ UPDATE `Reports` แถวนั้นแทนการ INSERT (`tasks.py:242-249`)

### 4.2 โมเดลความครบถ้วน + คอลัมน์ `tool_states`

เพิ่มคอลัมน์ `analysis.tool_states JSONB` เป็นข้อมูล**สำหรับตัดสินใจ** (เครื่องอ่าน)
โดยแยกจาก `tool_notes` ซึ่งคงไว้เป็นข้อความ**สำหรับแสดงผล** (คนอ่าน) — API ไม่เปลี่ยนสัญญา

```json
{
  "virustotal": {"state": "success"},
  "mobsf":      {"state": "gap", "reason": "exhausted", "message": "MobSF skipped after 120 status checks with no result"},
  "cape":       {"state": "success"},
  "rampart_ai": {"state": "terminal", "reason": "unsupported"}
}
```

`state` มี 3 ค่า:

| state | ความหมาย | ต้องวิเคราะห์ซ้ำ? |
|---|---|---|
| `success` | tool ผลิต report สำเร็จ และไฟล์ report อยู่บนดิสก์ | ไม่ |
| `terminal` | จบโดยเจตนา/เป็นไปไม่ได้: `reason` ∈ {`short_circuit`, `unsupported`, `oversize`} | ไม่ |
| `gap` | ควรมี report แต่ไม่มี: `reason` ∈ {`exhausted`, `missing_report`} | **ใช่** |

**tool ที่ถือว่าควรมี สำหรับเนื้อหาหนึ่ง** (ให้ตรงกับ pipeline จริง):

| tool | เงื่อนไขว่า "ควรมี" | อ้างอิง |
|---|---|---|
| virustotal | ทุกไฟล์ ยกเว้นใหญ่เกิน 32 MB → `terminal/oversize` | `task_handlers.py:81-86` |
| mobsf | นามสกุล ∈ {.apk, .ipa, .xapk, .jex, .dex, .apks, .aab} | `task_handlers.py:194` |
| cape | นามสกุล ∈ `CAPE_PACKAGE_MAP` | `task_handlers.py:298-367` |
| rampart_ai | เฉพาะเมื่อ mobsf สำเร็จ | `task_handlers.py:257-266` |
| gemini | synthesis — ไม่นับในความครบถ้วน (ล้มเหลวไม่บล็อก finalize) | `tasks.py:630-671` |

**แถวเก่าที่มี `tool_states` เป็น NULL** (ก่อน migrate) → ใช้การอนุมานย้อนหลัง:
`success` ถ้า tool อยู่ใน `tools` และไฟล์ report อ่านได้; `terminal` ถ้า `blocked_by == 'virustotal'`
(ใช้แทนการ match ข้อความ) หรือนามสกุลไม่รองรับ; นอกนั้นเป็น `gap`
→ ระบบทำงานได้กับข้อมูลเก่าโดยไม่ต้อง backfill

**Migration (ต้องทำก่อน deploy โค้ด):**

```sql
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS tool_states JSONB;
```

พร้อม mirror ใน `CREATE-SQL.sql` (ตาม AGENTS.md: `create_all` ไม่ ALTER ตารางเดิม)

### 4.3 Resolver ตัวเดียวสำหรับทุกเส้นทาง

แทนที่การเรียกสองฟังก์ชันเรียงกัน (`attempt_gap_fill_redispatch` → `attempt_attach_to_existing_analysis`)
ด้วยตัวตัดสินตัวเดียว ใช้ร่วมกันทั้ง `/upload` และ `/check-hash`:

```python
async def resolve_content_reuse(session, *, uid, file_hash, file_name, file_size, privacy) -> ReusePlan
```

ลำดับการตัดสิน (ภายใต้ `pg_advisory_xact_lock(hash)` ตามลำดับ lock เดิม: hash → task → refresh → write):

| # | เงื่อนไข | Plan | การทำงาน |
|---|---|---|---|
| 1 | มีแถวของเนื้อหาสถานะ `dispatching` | `busy` | คืน 409 ให้ลองใหม่ (เหมือนเดิม) |
| 2 | แถวของผู้ใช้เอง มีอยู่ และยังไม่ success **หรือ** success + ครบถ้วน | `reuse_user_row` | อัปเดต privacy เท่านั้น — ไม่สร้างแถว ไม่ dispatch — คืน `task_id`/`rid` เดิม (**G1**) |
| 3 | แถวของผู้ใช้เอง success แต่**ไม่ครบถ้วน** | `rerun_in_place` | re-point แถวเดิมไป run ใหม่ (task_id ใหม่, สถานะ dispatching→queued) + dispatch รอบซ่อม — **ไม่สร้างแถวใหม่, rid เดิม** (**G1+G3+G4**) ยกเว้นใช้ครบ `MAX_CONTENT_RERUNS` แล้วจะ fallback เป็นข้อ 4 |
| 4 | มี donor: success + ครบถ้วน | `attach` | upsert แถวของผู้ใช้ใหม่ แชร์ task_id/rid/status/tools ของ donor (**G2+G3**) |
| 5 | มี donor: success + ไม่ครบถ้วน | `attach_and_rerun` | สร้าง/อัปเดตแถวผู้ใช้พร้อม rid ของ donor แล้ว dispatch รอบซ่อมสำหรับเนื้อหา → แถวผู้ใช้ชี้ run ใหม่ (**G2+G3+G4**) |
| 6 | มี donor: กำลังวิเคราะห์ (`queued`/`processing`/`analyzing`) | `attach_wait` | upsert แถวผู้ใช้ให้แชร์ task_id + สถานะของ donor → รอ finalize ของ run นั้น (นี่คือ "task ที่รอผล" ตาม **G2** ไม่ต้องสร้าง task ชนิดใหม่) |
| 7 | ไม่มีอะไร reuse ได้ (หรือแถวล่าสุด failed) | `fresh` | เส้นทาง dispatch เดิม แต่ส่งต่อ report ที่มีอยู่บนดิสก์เป็น kwargs (ประหยัดงานที่ทำสำเร็จแล้ว) |

**การเลือก donor** (แก้ RC-5): เรียงลำดับความสำคัญ = success+ครบถ้วน → กำลังวิเคราะห์ → success+ไม่ครบถ้วน
ไม่ใช้ "ใหม่สุด" เป็นตัวตัดสินเพียงอย่างเดียว

**การเขียนแถวผู้ใช้** (แก้ RC-2): เปลี่ยนเป็น

```python
async def upsert_user_analysis(...)   # key = (uid, file_hash) เท่านั้น
```
- เจอแถวเดิม → UPDATE ในที่ (คง `file_name` เดิมไว้)
- ไม่เจอ → INSERT

### 4.4 รอบซ่อม (Gap Run) — วิเคราะห์เฉพาะ tool ที่ขาด และเขียนลง report เดิม

`dispatch_gap_run(session, donor_row, uid, ...)`:

1. **task_id ใหม่เสมอ** — จำเป็น เพราะ run เดิมจบแล้ว (`success`) และ `task_is_complete()`
   จะทำให้ run ซ้ำบน task_id เดิมกลายเป็น no-op (`tasks.py:118-121, 339-343`)
2. **kwargs ส่งต่อผลที่ทำสำเร็จแล้ว** จาก `tool_states` ของ donor:
   - tool ที่ `success` → `{tool}_status=True` + `{tool}_report_path=reports/{tool}-{md5}.json`
     (รวม `rampart_ai` ด้วย — แก้ RC-6)
   - tool ที่ `terminal` → `{tool}_status="skipped"` + คง note เดิมไว้ให้ UI อธิบาย
   - tool ที่ `gap` → ไม่ส่งอะไร → pipeline จะวิเคราะห์เฉพาะตัวนี้
3. **ทุกแถวของ run ใหม่ถือ `rid` เดิมของเนื้อหา** → `finalize_analysis_report` เห็น rid เดียว
   → UPDATE `Reports` แถวเดิม (ได้ R3) → report ใบเดียวของไฟล์ถูกเติมผลของ tool ที่เพิ่งสำเร็จ
   โดยผู้ใช้คนอื่นที่แชร์ rid นี้จะเห็นข้อมูลที่ครบขึ้นด้วย (ตรงตามเป้าหมาย "ไฟล์เดียวกันใช้ report เดิม")
4. **มีขอบเขต** (แก้ S10): `MAX_CONTENT_RERUNS = 3` — นับจำนวน run ของเนื้อหาจาก
   `count(distinct task_id)` ของแถวทั้งหมดที่มี sha256 เดียวกัน (นับเป็น "รอบ" ไม่ใช่ "แถว"
   ผู้ใช้ที่ attach แชร์ task_id เดิมจึงไม่ทำให้ตัวนับพอง) เมื่อใช้ครบ 3 รอบซ่อมแล้ว
   การอัปโหลดครั้งถัดไปจะได้ `attach` (แถวเดิม) แทนการยิงรอบใหม่ พร้อม `completeness.missing`
   บอกว่า tool ใดยังขาด — ตัวนับถูกเก็บใน DB จึงไม่ต้องมีคอลัมน์เพิ่มและไม่ต้องใช้ cooldown ตามเวลา
   (ใช้ไม่ได้จริง เพราะกรณี re-point แถวเดิมไม่มีการสร้างแถวใหม่ให้ดูเวลา)
5. **กรณี `Reports` แถวเดิมถูกลบไปแล้ว** → dispatch เป็นรอบใหม่ของเนื้อหา (สร้าง report ใหม่)
   ซึ่งเป็นกรณีเดียวที่การสร้าง report ใหม่ถือว่าถูกต้อง

### 4.5 การแก้ฝั่ง pipeline (`bgProcessing/tasks.py`)

| จุด | การแก้ |
|---|---|
| `analyze_malware_task` | รับ/ส่ง `tool_states` ผ่าน retry kwargs เช่นเดียวกับ `tool_notes` |
| `evaluate_tool_progress` | คืน `reason` กำกับ (เช่น `exhausted`) เพื่อให้ประกอบ `tool_states` ได้ |
| handler ของ tool | คืน `reason` ชัดเจน: `unsupported` (นามสกุล), `oversize` (VT), `short_circuit` (VT=100) |
| เส้นทาง VT=100 | เขียน `tool_states` = virustotal success + อื่น ๆ `terminal/short_circuit` (ใช้ร่วมกับ `blocked_by="virustotal"` ที่มีอยู่) |
| `finalize_analysis_report` | เขียน `tool_states` พร้อมกับ `tools`/`tool_notes` ใน UPDATE เดียวกัน |

### 4.6 การเสริมความแข็งของ DB

ไฟล์พร้อมรัน (ไม่มีคอมเมนต์ในไฟล์ SQL ตามสไตล์ repo):

| ไฟล์ | ใช้เมื่อ | ทำอะไร |
|---|---|---|
| `docs/migrations/2026-09-28-analysis-dedup-phase0.sql` | **บังคับ** ก่อน deploy โค้ด | เพิ่มคอลัมน์ `tool_states`, soft delete แถว `(task_id, uid)` ซ้ำทุกแถวเกินหนึ่ง (เก็บแถวที่มี `rid` ก่อน แล้วจึงใหม่สุด), สร้าง unique index, และ SELECT ตรวจผลหลังรัน |
| `docs/migrations/2026-09-28-analysis-dedup-history-cleanup.sql` | ทางเลือก สำหรับล้างข้อมูลซ้ำเดิม | แสดงตัวอย่างก่อนว่าแถวใดจะถูกซ่อน แล้ว soft delete แถวซ้ำของ `(uid, file_hash)` ให้เหลือแถวที่ดีที่สุดหนึ่งแถวต่อไฟล์ต่อผู้ใช้ |

การย้อนกลับ: การลบของ migration ตั้ง `deleted_by` เป็น NULL ขณะที่การลบผ่าน API/UI ตั้ง `deleted_by` เป็น uid ผู้กระทำเสมอ (`services/admin/admin_service.py:715-716`) จึงย้อนกลับได้ด้วย
`UPDATE "analysis" SET "deleted_at" = NULL WHERE "deleted_at" IS NOT NULL AND "deleted_by" IS NULL;`

```sql
CREATE UNIQUE INDEX IF NOT EXISTS "uq_analysis_task_uid_active"
  ON "analysis" ("task_id", "uid") WHERE "deleted_at" IS NULL;
```

- mirror ลง `CREATE-SQL.sql` (ให้ตรงกับ model ที่ `schema_class.py:67-75`)
- **ตรวจก่อนสร้าง** ว่ามีข้อมูลละเมิดอยู่หรือไม่ (ถ้ามี ต้องจัดการก่อน ไม่งั้นสร้าง index ไม่ผ่าน):

```sql
SELECT task_id, uid, count(*)
FROM analysis
WHERE deleted_at IS NULL AND task_id IS NOT NULL
GROUP BY task_id, uid HAVING count(*) > 1;
```

### 4.7 สัญญา API (เพิ่มเติมเท่านั้น ไม่ทำลายของเดิม)

`upload_response` และ `/check-hash` เพิ่มฟิลด์:

| ฟิลด์ | ค่า | ความหมาย |
|---|---|---|
| `queue_state` | `dispatched` / `reused` / `gap_filled` / **`waiting`** (ใหม่) | `waiting` = ผูกกับ run ที่กำลังวิเคราะห์อยู่ (goal 2) |
| `completeness` | `{"missing": ["mobsf"], "terminal": ["cape"]}` | ให้ frontend อธิบายได้ว่าทำไมต้องวิเคราะห์ซ้ำ |

ค่า `queue_state` เดิมทั้งสามค่ายังคงความหมายเดิม → frontend ที่มีอยู่ไม่พัง

---

## 5. เกณฑ์ยอมรับ (Acceptance Criteria)

| เป้าหมาย | เกณฑ์ที่วัดได้ |
|---|---|
| G1 ผู้ใช้คนเดิม + ไฟล์เดิม → ใช้ analysis เดิม | อัปโหลดซ้ำ (ชื่อเดิมหรือเปลี่ยนชื่อก็ตาม) → จำนวนแถว `analysis` ของ `(uid, hash)` ยังเป็น 1, ไม่มี task ใหม่เมื่อวิเคราะห์ครบแล้ว |
| G2 ผู้ใช้ใหม่ + ไฟล์ที่เคยวิเคราะห์ → แถวใหม่ + ใช้ report/สถานะเดิม | ผู้ใช้ใหม่ได้ `task_id` และ `rid` เดิม, ไม่มี Celery task ใหม่; ถ้า donor ยังไม่เสร็จ → แถวใหม่รอผล run เดียวกัน แล้วได้ rid เดียวกันเมื่อ finalize |
| G3 ไฟล์เดียวกัน → report เดิม | จำนวนแถว `reports` ต่อ 1 `file_hash` = 1 แม้ผ่านรอบซ่อมหรือมีผู้ใช้หลายคน |
| G4 success แล้วแต่ tool ไม่ครบ → วิเคราะห์เฉพาะที่ขาด | รอบซ่อมส่ง kwargs เฉพาะ tool ที่ `gap`; tool ที่ `terminal` ไม่ถูกเรียก; ไฟล์ที่ครบแล้วไม่มีการ dispatch ใด ๆ |

---

## 6. แผนทดสอบ

| # | สถานการณ์ | ชนิด | คาดหวัง |
|---|---|---|---|
| T1 | ผู้ใช้เดิม อัปโหลดไฟล์เดิม ชื่อใหม่ | unit+api | 1 แถว, ไม่มี task ใหม่, rid เดิม |
| T2 | ผู้ใช้เดิม อัปโหลดไฟล์ที่ครบสมบูรณ์ | api | 0 แถวใหม่, 0 task, `queue_state=reused` |
| T3 | ผู้ใช้เดิม อัปโหลดไฟล์ที่ตัวเองมี gap | api | 0 แถวใหม่, แถวเดิมถูก re-point ไป run ใหม่, rid เดิม |
| T4 | ผู้ใช้ใหม่ + donor กำลังวิเคราะห์ | api | แถวใหม่แชร์ task_id, ไม่ dispatch; จำลอง finalize → ทั้งสองแถวได้ rid เดียวกัน |
| T5 | ผู้ใช้ใหม่ + donor ครบถ้วน | api | แถวใหม่, rid/task_id เดิม, ไม่ dispatch |
| T6 | ผู้ใช้ใหม่ + donor มี gap | api | แถวใหม่ + รอบซ่อม reuse report ที่มีอยู่, `reports` ยังมีแถวเดียว |
| T7 | แถว VT=100 (`blocked_by=virustotal`) | service | ห้าม gap-fill เด็ดขาด |
| T8 | MobSF นามสกุลไม่รองรับ | service | `terminal` ไม่ re-run |
| T9 | ไฟล์ report บนดิสก์หาย แต่ `tools` ระบุว่าสำเร็จ | service | กลายเป็น `gap` → re-run เฉพาะตัวนั้น |
| T10 | อัปโหลดซ้ำระหว่างรอบซ่อมยัง queued | api | attach (wait) ไม่สร้างรอบที่สอง (bounded) |
| T11 | DB: insert แถว `(task_id, uid)` ซ้ำ | db | IntegrityError (พิสูจน์ว่า index ทำงาน) |
| T12 | ลำดับ lock: hash → task → refresh → write | unit | คงเดิมตาม `tests/test_analysis_upload.py:336` |

---

## 7. ลำดับการ rollout

| Phase | งาน | หมายเหตุ |
|---|---|---|
| 0 | รัน `docs/migrations/2026-09-28-analysis-dedup-phase0.sql` (คอลัมน์ + ล้างแถวซ้ำที่บล็อก index + unique index) | **ต้องเสร็จก่อน deploy โค้ด** เพราะ ORM จะอ้างคอลัมน์ใหม่ |
| 1 | `resolve_content_reuse` + `upsert_user_analysis` (key = uid+hash) + เดินสายเข้า `/upload` และ `/check-hash` + T1, T2, T4, T5, T12 | แก้ RC-1(บางส่วน), RC-2 |
| 2 | `tool_states` ทั้ง pipeline + `dispatch_gap_run` + carry-forward (รวม rampart_ai) + T3, T6, T7, T8, T9, T10 | แก้ RC-1, RC-3, RC-4, RC-6 |
| 3 | (ทางเลือก) backfill `tool_states` ของแถวเก่า, แสดงสถานะ "วิเคราะห์ไม่ครบ" บน dashboard | ไม่เร่งด่วน เพราะมี fallback อนุมาน |
| 4 | (ทางเลือก) รัน `history-cleanup.sql` เพื่อซ่อน analysis ซ้ำเดิมของผู้ใช้แต่ละคน | ไฟล์แสดงรายการก่อนลบทุกครั้ง และย้อนกลับได้ |

---

## 8. ความเสี่ยงและข้อแลกเปลี่ยน

| ประเด็น | รายละเอียด | แนวทาง |
|---|---|---|
| Report ถูกแก้ไขย้อนหลัง | รอบซ่อมเขียนทับ `Reports` เดิม → ผู้ใช้คนอื่นที่แชร์ report เห็นคะแนนที่ครบขึ้น (และ `created_at` เดิม) | เป็นเจตนาของ G3; ถ้าต้องการประวัติแบบ immutable ต้องออกแบบ report versioning ซึ่งใหญ่กว่า — บันทึกเป็นความเสี่ยงที่ยอมรับ |
| แถวผู้ใช้ถูก re-point (task_id เปลี่ยน) | แท็บเก่าที่ poll `task_id` เดิมของแถวนั้นจะได้ `TASK_NOT_FOUND` | เกิดเฉพาะกรณี "แถวตัวเองไม่ครบ → ซ่อม" ; response ของ upload/check-hash คืน task_id ใหม่เสมอ |
| ต้นทุนการซ่อมอัตโนมัติ | tool ที่พังถาวรจะถูกยิงซ้ำทุกครั้งที่อัปโหลด | จำกัด 3 รอบซ่อมต่อเนื้อหา (`MAX_CONTENT_RERUNS`, ข้อ 4.4) แล้วเสิร์ฟ report ที่มีอยู่พร้อมระบุ tool ที่ขาด |
| ลำดับ migration | ถ้า deploy โค้ดก่อน ALTER → INSERT ที่อ้าง `tool_states` จะ error | บังคับลำดับ Phase 0 → 1/2 |
| แถวซ้ำเดิมในฐานข้อมูล | index สร้างไม่ผ่านถ้ามีข้อมูลละเมิด | query ตรวจในข้อ 4.6 + จัดการก่อน (soft delete เฉพาะที่เจ้าของอนุมัติ) |

---

## 9. ขอบเขตที่ไม่ทำ (Out of Scope)

- ไม่ลบหรือ soft-delete แถวซ้ำเดิมอัตโนมัติ — ให้รายงาน dry-run แล้วเจ้าของระบบตัดสินใจ
- ไม่ทำ report versioning / audit trail ของการเปลี่ยนแปลงคะแนน
- ไม่เพิ่ม endpoint "บังคับวิเคราะห์ใหม่" (force re-analyze) — ถ้าต้องการ ควรเพิ่มธงแยกในภายหลัง
- ไม่แตะ `recovery.py` (การกู้ task ที่ค้าง) ในเฟสนี้; แต่แนะนำให้ใช้ helper สร้าง kwargs
  ชุดเดียวกับรอบซ่อมในอนาคต เพื่อไม่ให้วิเคราะห์ซ้ำ tool ที่มี report อยู่แล้ว
