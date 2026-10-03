# RAMPART API

เอกสารนี้อธิบาย API ทั้งหมดของ RAMPART FastAPI จากโค้ดปัจจุบัน เพื่อให้ frontend หรือ agent อื่นสร้างเว็บและเชื่อมต่อได้ถูกต้อง

## 1. ข้อมูลพื้นฐาน

| รายการ | ค่า |
|---|---|
| Framework | FastAPI |
| Version | `1.0.0` |
| Default base URL | `http://localhost:8006` |
| Production base URL | ใช้ hostname ของ server จริง เช่น `https://api.example.com` |
| JSON content type | `application/json` |
| API version | analysis ใช้ `/api/analy/v1` |
| Interactive OpenAPI | `GET /docs` |
| ReDoc | `GET /redoc` |
| OpenAPI JSON | `GET /openapi.json` |
| CORS | เปิดทุก origin, method และ header |
| Timezone ของ Celery | `Asia/Bangkok` |
| เวลาใน response ส่วนใหญ่ | ISO 8601 string เช่น `2026-09-24T10:30:00+00:00` |

FastAPI ใช้ path ตามที่ระบุด้านล่าง ไม่มี trailing slash

### กติกาสำคัญสำหรับ frontend

1. **Access token ส่งใน JSON body** ของ endpoint ส่วนใหญ่ ไม่ใช่ `Authorization: Bearer`
2. มีเพียง `GET /api/analy/v1/download/report/{file_name}` ที่รองรับ Bearer header
3. `POST /api/analy/v1/upload` ใช้ `upload_token` ไม่ใช้ access token
4. `POST /api/profile/avatar` ส่ง access token เป็น form field
5. `POST /api/auth/login` รับ `deviceToken` เป็น HTTP header
6. OAuth ต้องใช้ browser navigation เพราะ server ตอบกลับด้วย HTTP `302`
7. อย่าตรวจทุก field จากภาษาไทยหรือ HTTP status เพียงอย่างเดียว ให้ดู `success`, `status`, `code`, `detail` ตามรูปแบบ response ด้วย
8. ค่า `privacy: true` หมายถึง **รายงานส่วนตัว** (ค่าเริ่มต้น) ส่วน `privacy: false` หมายถึงรายงานสาธารณะ

### ตัวอย่าง client กลาง

```ts
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8006"

export class ApiError extends Error {
  constructor(
    public httpStatus: number,
    public body: unknown,
    message: string,
  ) {
    super(message)
  }
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...init.headers,
    },
  })

  const contentType = response.headers.get("content-type") ?? ""
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text()

  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null && "message" in body
        ? String((body as { message: unknown }).message)
        : response.statusText
    throw new ApiError(response.status, body, message)
  }

  if (
    typeof body === "object" &&
    body !== null &&
    "success" in body &&
    (body as { success: unknown }).success === false
  ) {
    const message =
      "message" in body ? String((body as { message: unknown }).message) : "Request failed"
    throw new ApiError(response.status, body, message)
  }

  return body as T
}

export function jsonBody(value: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  }
}
```

> บาง endpoint สำเร็จด้วย HTTP `200` แต่ส่ง `success: false` ดังนั้น client ต้องตรวจทั้ง HTTP status และ `success`

---

## 2. Authentication และ Authorization

### JWT ที่ระบบใช้

| Token | ใช้กับ | อายุ |
|---|---|---:|
| `access` | endpoint ส่วนใหญ่ | 7 วัน |
| `refresh_token` | ต่ออายุ access token | 7 วัน |
| `device` | ข้าม OTP ใน login ถัดไป | 7 วัน |
| `login` | ยืนยัน OTP การ login | 5 นาที |
| `register` | ยืนยัน OTP การสมัคร | 5 นาที |
| `reset-passwd` | ยืนยัน OTP การรีเซ็ตรหัสผ่าน | 5 นาที |
| `upload` | อนุญาต upload ไฟล์ | 15 นาที |

JWT payload หลักมี `sub`, `type`, `iat`, `exp` โดย `sub` ของ access token เป็น `uid` ของผู้ใช้

### การเก็บ token ฝั่ง frontend

```ts
localStorage.setItem("access_token", response.data.access_token)
localStorage.setItem("refresh_token", response.data.refresh_token)
localStorage.setItem("device_token", response.data.deiveToken)
```

`deiveToken` เป็นชื่อ field จริงของ response ที่มี typo ห้ามแก้เป็น `deviceToken` ใน contract

เมื่อเรียก endpoint ที่ต้องยืนยันตัวตน:

```ts
const accessToken = localStorage.getItem("access_token")

await apiFetch("/api/profile", jsonBody({
  token: accessToken,
}))
```

### OAuth

- Provider: `google` หรือ `github`
- OAuth flow ทั้งหมดเกิดที่ Next.js (`/api/auth/{provider}/login` → provider → `/api/auth/{provider}/callback`) แล้วส่ง credential ที่ได้กลับมาที่นี่
- Google ส่ง `id_token` (ยืนยันด้วย JWKS ของ Google + `GOOGLE_CLIENT_ID`) — backend ไม่ต้องมี client secret ของ provider เลย
- GitHub ส่ง `access_token` (ถาม `api.github.com/user` ว่า token นี้เป็นใคร)
- คืน access token ชนิดเดียวกับ password login
- OAuth-only account ไม่มีรหัสผ่านใน DB
- หาก account ผูก OAuth แล้ว การ password login ต้องใช้ OTP เสมอ แม้มี device token

### Role

| Role | สิทธิ์ |
|---|---|
| `user` | ใช้งานระบบวิเคราะห์และดูรายงานส่วนตัว |
| `admin` | เข้า admin panel; จัดการผู้ใช้และไฟล์ของ `user` |
| `master` | ทุกสิทธิ์ของ admin; เปลี่ยน role เป็น `user` หรือ `admin` ได้ |

กฎ admin:

- เป้าหมาย role `master` ห้ามถูกจัดการโดยทุกคน รวมถึง master ตัวเอง
- `admin` จัดการ `admin` หรือ `master` ไม่ได้
- `master` จัดการ `admin` และ `user` ได้
- `admin` จัดการ `user` ได้
- บัญชีถูก ban ใช้ admin panel ไม่ได้
- role และ ban state ถูกอ่านจาก DB ทุก request ไม่เชื่อ role ที่อยู่ใน JWT

---

## 3. รูปแบบ Response และ Error

### Envelope มาตรฐาน

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "ข้อความ",
  "data": {}
}
```

Error envelope:

```json
{
  "success": false,
  "status": "TOKEN_INVALID",
  "message": "โทเค็นไม่ถูกต้องหรือหมดอายุ",
  "data": null
}
```

### รูปแบบที่ต่างจาก envelope

1. Analysis upload/check-hash/history และ dashboard บาง endpoint คืน object โดยตรง
2. `POST /api/analy/v1/dashboard/recent-activities` คืน array โดยตรง
3. Admin list คืน `{ "success": true, "data": [...], "pagination": {...} }` โดยไม่มี `status`, `message`
4. CSV export คืน text
5. Download report/avatar คืนไฟล์
6. `HTTPException` คืน `{ "detail": ... }`
7. Validation `422` คืน `{ "detail": [...] }`

ตัวอย่าง `HTTPException`:

```json
{
  "detail": "Invalid upload token"
}
```

ตัวอย่าง validation `422`:

```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "sha256"],
      "msg": "sha256 must be a 64-character hex string",
      "input": "bad"
    }
  ]
}
```

### Status code ที่พบ

| HTTP | ความหมาย |
|---:|---|
| `200` | สำเร็จ หรือ business error ที่ controller คืนเป็น `success: false` |
| `201` | สร้าง test user ใหม่ |
| `302` | OAuth redirect |
| `400` | ข้อมูล/path ไม่ถูกต้อง |
| `401` | token ไม่ถูกต้อง หมดอายุ หรือไม่มีสิทธิ์เข้าถึง resource |
| `403` | account ถูก ban หรือสิทธิ์ไม่พอ |
| `404` | ไม่พบ user/task/report/file |
| `409` | ข้อมูลซ้ำ หรือ dispatch ชนกัน |
| `413` | ไฟล์ใหญ่เกินขีดจำกัด |
| `422` | body/query/form ไม่ตรง schema |
| `500` | ข้อผิดพลาดภายใน |
| `503` | Redis, Celery, database หรือ OAuth provider ไม่พร้อม |

### Auth status codes ที่ frontend ควรรองรับ

`LOGIN_SUCCESS`, `USER_NOT_FOUND`, `USERNAME_TAKEN`, `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_WRONG_TYPE`, `OAUTH_PROVIDER_ERROR`, `OAUTH_EMAIL_MISSING`, `OAUTH_ACCOUNT_LINKED`, `PROFILE_UPDATE_SUCCESS`, `AVATAR_UPDATE_SUCCESS`, `INVALID_FILE_TYPE`, `FILE_TOO_LARGE`, `RATE_LIMITED`, `ACCOUNT_BANNED`, `INSUFFICIENT_ROLE`, `MASTER_PROTECTED`, `ADMIN_TARGET_FORBIDDEN`, `INVALID_ROLE_TARGET`, `TARGET_NOT_FOUND`, `BAN_SUCCESS`, `UNBAN_SUCCESS`, `ROLE_CHANGE_SUCCESS`, `ADMIN_ACTION_SUCCESS`, `INVALID_CREDENTIALS`, `OTP_SENT`, `OTP_INVALID`, `OTP_WRONG`, `OTP_LOCKED`, `OTP_EXPIRED`, `REGISTER_SUCCESS`, `PASSWORD_RESET_SUCCESS`, `TOKEN_REFRESH_SUCCESS`

### OTP

- เป็นตัวเลข 6 หลัก
- อายุ 5 นาที
- ผิดได้สูงสุด 5 ครั้ง
- หลังผิดครบ 5 ครั้งจะ lockout จน OTP หมดอายุ
- Lockout แยกตาม action และ identifier:
  - register: email
  - login/reset: `uid`
- การขอ OTP ใหม่ด้วย token ใหม่ไม่สามารถข้าม lockout เดิมได้

---

## 4. รายการ Endpoint ทั้งหมด

### System

| Method | Path | Auth | รายละเอียด |
|---|---|---|---|
| `GET` | `/` | ไม่ | health check |
| `GET` | `/scan` | ไม่ | คืนไฟล์ `scan.html` |
| `GET` | `/docs` | ไม่ | Swagger UI ที่ FastAPI สร้าง |
| `GET` | `/redoc` | ไม่ | ReDoc ที่ FastAPI สร้าง |
| `GET` | `/openapi.json` | ไม่ | OpenAPI schema |

### Auth

| Method | Path | Auth | รายละเอียด |
|---|---|---|---|
| `POST` | `/api/auth/register` | ไม่ | ขอ OTP สมัครสมาชิก |
| `POST` | `/api/auth/register/confirm` | register token | ยืนยัน OTP สมัครสมาชิก |
| `POST` | `/api/auth/login` | ไม่ | login ด้วย email/password |
| `POST` | `/api/auth/login/confirm` | login token | ยืนยัน OTP login |
| `POST` | `/api/auth/reset-passwd` | ไม่ | ขอ OTP หรือเปลี่ยนรหัสผ่านด้วย access token |
| `POST` | `/api/auth/reset-passwd/confirm` | reset token | ยืนยัน OTP รีเซ็ตรหัสผ่าน |
| `POST` | `/api/auth/refresh` | refresh token | ออก access/refresh token ใหม่ |
| `POST` | `/api/auth/{provider}/exchange` | ไม่ | ยืนยัน credential จาก OAuth ที่เว็บแอปทำไว้ |

### Profile

| Method | Path | Auth | รายละเอียด |
|---|---|---|---|
| `POST` | `/api/profile` | access token ใน body | ดูโปรไฟล์ |
| `PATCH` | `/api/profile` | access token ใน body | เปลี่ยน username |
| `POST` | `/api/profile/login-history` | access token ใน body | ประวัติ login ล่าสุด 50 รายการ |
| `POST` | `/api/profile/download` | access token ใน body | บันทึกประวัติการดาวน์โหลด |
| `POST` | `/api/profile/download-history` | access token ใน body | ประวัติดาวน์โหลดล่าสุด 50 รายการ |
| `POST` | `/api/profile/avatar` | access token ใน form | อัปโหลด/เปลี่ยน avatar |
| `GET` | `/api/profile/avatar/{file_name}` | ไม่ | ดาวน์โหลด avatar |

### Analysis

| Method | Path | Auth | รายละเอียด |
|---|---|---|---|
| `POST` | `/api/analy/v1/generate-token` | access token ใน body | สร้าง upload token |
| `POST` | `/api/analy/v1/check-hash` | access token ใน body | ตรวจ dedup จาก SHA-256 |
| `POST` | `/api/analy/v1/upload` | upload token | อัปโหลดและส่ง analysis |
| `POST` | `/api/analy/v1/task_id` | access token ใน body | ดูสถานะ/ผลลัพธ์ |
| `POST` | `/api/analy/v1/report_target` | access token ใน body | ดู raw report ของ tool |
| `GET` | `/api/analy/v1/download/report/{file_name}` | Bearer หรือ query token | ดาวน์โหลด raw report |
| `POST` | `/api/analy/v1/history` | access token ใน body | ประวัติของผู้ใช้เอง |
| `PATCH` | `/api/analy/v1/{task_id}/privacy` | access token ใน body | เปลี่ยน privacy |

### Dashboard

| Method | Path | Auth | รายละเอียด |
|---|---|---|---|
| `POST` | `/api/analy/v1/dashboard/summary` | access token ใน body | สถิติ dashboard |
| `POST` | `/api/analy/v1/dashboard/recent-activities` | access token ใน body | กิจกรรมล่าสุด |
| `POST` | `/api/analy/v1/dashboard/reports` | access token ใน body | รายงานสาธารณะ |

### Admin

ทุก endpoint ต้องส่ง access token ใน JSON body และ actor ต้องเป็น `admin` หรือ `master`

| Method | Path | รายละเอียด |
|---|---|---|
| `POST` | `/api/admin/users` | รายชื่อผู้ใช้ |
| `POST` | `/api/admin/users/detail` | รายละเอียดผู้ใช้ |
| `POST` | `/api/admin/users/history` | ประวัติ analysis ของผู้ใช้ |
| `POST` | `/api/admin/users/login-history` | ประวัติ login ของผู้ใช้ |
| `POST` | `/api/admin/users/download-history` | ประวัติดาวน์โหลดของผู้ใช้ |
| `POST` | `/api/admin/users/ban` | ban ผู้ใช้ |
| `POST` | `/api/admin/users/unban` | unban ผู้ใช้ |
| `POST` | `/api/admin/users/role` | เปลี่ยน role โดย master |
| `POST` | `/api/admin/users/bulk-ban` | ban หลายผู้ใช้ |
| `POST` | `/api/admin/dashboard/summary` | สถิติระบบสำหรับ admin |
| `POST` | `/api/admin/audit-logs` | audit logs |
| `POST` | `/api/admin/files` | รายการไฟล์ทั้งระบบ |
| `POST` | `/api/admin/files/delete` | soft delete ไฟล์ |
| `POST` | `/api/admin/files/bulk-delete` | soft delete หลายไฟล์ |
| `POST` | `/api/admin/reports` | รายการ report ที่เสร็จแล้ว |
| `POST` | `/api/admin/export/users` | export users เป็น CSV |
| `POST` | `/api/admin/export/files` | export files เป็น CSV |
| `POST` | `/api/admin/export/audit-logs` | export audit logs เป็น CSV |
| `POST` | `/api/admin/broadcast-email` | ส่ง email ถึงผู้ใช้ |
| `POST` | `/api/admin/system/health` | ตรวจ PostgreSQL, Redis, Celery, services |
| `POST` | `/api/admin/tasks` | รายการ task |
| `POST` | `/api/admin/tasks/depth` | จำนวน task ใน queue |
| `POST` | `/api/admin/tasks/retry` | retry task |
| `POST` | `/api/admin/tasks/cancel` | cancel task |
| `POST` | `/api/admin/rate-limits` | ดู OTP/profile rate limits |
| `POST` | `/api/admin/rate-limits/clear` | ล้าง rate-limit key |

### Test mode

ใช้ได้เมื่อ environment เปิด `TEST_MODE=TRUE` เท่านั้น เป็นเครื่องมือทดสอบ ห้ามใช้เป็น auth ของ production

| Method | Path | รายละเอียด |
|---|---|---|
| `GET` | `/test` | test console HTML |
| `GET` | `/test/api/status` | สถานะ test mode/DB/Redis/user |
| `POST` | `/test/api/user` | สร้างหรือ reactivate test user |
| `POST` | `/test/api/token` | สร้าง test access/upload token |
| `GET` | `/test/api/analysis/{task_id}` | ดู diagnostics ของ task |

---

## 5. Auth API

## 5.1 `POST /api/auth/register`

ส่ง OTP เพื่อสมัครสมาชิก ยังไม่สร้าง user จนกว่าจะยืนยัน OTP

### Request

```json
{
  "username": "analyst01",
  "email": "analyst@example.com",
  "password": "secret-password"
}
```

| Field | Type | Required | หมายเหตุ |
|---|---|---|---|
| `username` | string | ใช่ | schema ไม่บังคับความยาวใน endpoint นี้ |
| `email` | string | ใช่ | normalize เป็น lowercase/trim |
| `password` | string | ใช่ | hash ด้วย Argon2 ตอนยืนยัน |

### Success

```json
{
  "success": true,
  "status": "OTP_SENT",
  "message": "รหัส OTP ถูกส่งไปยังอีเมล analyst@example.com",
  "data": {
    "token": "<register-jwt>",
    "expires_in": 300
  }
}
```

Email ซ้ำคืน HTTP `200` แต่ `success: false`, `status: USER_NOT_FOUND`, message ว่ามีอีเมลนี้อยู่แล้ว

## 5.2 `POST /api/auth/register/confirm`

```json
{
  "token": "<register-jwt>",
  "otp": "123456",
  "username": "analyst01"
}
```

`username` เป็น optional และถูก override จาก username ที่ token ลงทะเบียนไว้

```json
{
  "success": true,
  "status": "REGISTER_SUCCESS",
  "message": "ลงทะเบียนผู้ใช้งานสำเร็จ",
  "data": null
}
```

หลังสำเร็จให้เริ่ม login ใหม่

## 5.3 `POST /api/auth/login`

### Request

```json
{
  "email": "analyst@example.com",
  "password": "secret-password"
}
```

Header ไม่บังคับ:

```http
deviceToken: <device-jwt>
```

### OTP required

```json
{
  "success": true,
  "status": "OTP_SENT",
  "message": "รหัส OTP ถูกส่งไปยังอีเมล analyst@example.com",
  "data": {
    "token": "<login-jwt>",
    "expires_in": 300
  }
}
```

### Device token bypass OTP

เกิดเมื่อทุกเงื่อนไขต่อไปนี้ผ่าน:

1. ส่ง `deviceToken`
2. token ยังไม่หมดอายุ
3. token `sub` ตรงกับ `uid` ของ account
4. token `email` ตรงกับ email ของ account
5. account ไม่มี OAuth account ที่ link ไว้

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "เข้าสู่ระบบสำเร็จ",
  "data": {
    "access_token": "<access-jwt>",
    "data": {},
    "bypass_otp": true,
    "device_token": "<new-device-jwt>"
  }
}
```

Response นี้ไม่มี `refresh_token` หากต้องการ refresh ควร login แบบ OTP เพื่อรับ refresh token

## 5.4 `POST /api/auth/login/confirm`

```json
{
  "token": "<login-jwt>",
  "otp": "123456"
}
```

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "ยืนยันการเข้าสู่ระบบสำเร็จ",
  "data": {
    "access_token": "<access-jwt>",
    "data": {
      "uid": "<uuid>",
      "email": "analyst@example.com",
      "role": "user",
      "username": "analyst01",
      "status": "active",
      "created_at": "2026-09-24T10:30:00"
    },
    "deiveToken": "<device-jwt>",
    "refresh_token": "<refresh-jwt>"
  }
}
```

## 5.5 `POST /api/auth/reset-passwd`

Endpoint นี้มีสองโหมด

### โหมดขอ OTP

```json
{
  "email": "analyst@example.com"
}
```

คืน:

```json
{
  "success": true,
  "status": "OTP_SENT",
  "message": "รหัส OTP ถูกส่งไปยังอีเมล analyst@example.com",
  "data": {
    "token": "<reset-jwt>",
    "expires_in": 300
  }
}
```

### โหมดเปลี่ยนทันทีด้วย access token

```json
{
  "token": "<access-jwt>",
  "newPasswd": "new-password"
}
```

คืน `PASSWORD_RESET_SUCCESS` โดยไม่ต้องใช้ OTP

## 5.6 `POST /api/auth/reset-passwd/confirm`

```json
{
  "token": "<reset-jwt>",
  "otp": "123456",
  "newPasswd": "new-password"
}
```

คืน:

```json
{
  "success": true,
  "status": "PASSWORD_RESET_SUCCESS",
  "message": "รีเซ็ตรหัสผ่านสำเร็จ",
  "data": null
}
```

## 5.7 `POST /api/auth/refresh`

```json
{
  "refresh_token": "<refresh-jwt>"
}
```

```json
{
  "success": true,
  "status": "TOKEN_REFRESH_SUCCESS",
  "message": "รีเฟรชโทเค็นสำเร็จ",
  "data": {
    "access_token": "<new-access-jwt>",
    "refresh_token": "<new-refresh-jwt>"
  }
}
```

ควรแทน refresh token เดิมทุกครั้งที่ refresh สำเร็จ

## 5.8 `POST /api/auth/{provider}/exchange`

ตัวอย่าง:

```text
POST /api/auth/google/exchange   {"id_token": "<google id token>"}
POST /api/auth/github/exchange  {"access_token": "<github access token>"}
```

สำเร็จ:

```json
{"success": true, "status": "LOGIN_SUCCESS", "message": "เข้าสู่ระบบสำเร็จ",
 "data": {"access_token": "<jwt>", "device_token": "<jwt>", "data": {"uid": "…", "role": "user", …}}}
```

ล้มเหลว: `{"success": false, "status": "OAUTH_PROVIDER_ERROR", "message": "..."}`
หรือ `OAUTH_ACCOUNT_LINKED` เมื่อผูกกับบัญชีเดิมไม่ได้

- Provider อื่น: `404 {"detail":"Unsupported OAuth provider"}`
- ยังไม่ตั้ง `GOOGLE_CLIENT_ID`: `503 {"detail":"..."}`

Backend ไม่เก็บ client secret ของ provider ใด ๆ — Google ยืนยันจาก JWKS สาธารณะ, GitHub ถาม provider โดยตรง

---

## 6. Profile API

## 6.1 โครงสร้าง User ที่ frontend ใช้

```json
{
  "uid": "<uuid>",
  "username": "analyst01",
  "email": "analyst@example.com",
  "avatar_url": "/api/profile/avatar/<random-token>.png",
  "role": "user",
  "status": "active",
  "created_at": "2026-09-24T10:30:00"
}
```

`avatar_url` เป็น `null` เมื่อยังไม่อัปโหลด และเป็น path ของ API server ไม่ใช่ absolute URL

## 6.2 `POST /api/profile`

ดึงข้อมูล profile ของ token owner

```json
{
  "token": "<access-jwt>"
}
```

คืน:

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "ดึงข้อมูลโปรไฟล์สำเร็จ",
  "data": {}
}
```

## 6.3 `PATCH /api/profile`

```json
{
  "token": "<access-jwt>",
  "username": "new_name"
}
```

กติกา:

- ปฏิเสธ field อื่นนอกจาก `token`, `username`
- username 3-50 ตัวอักษร
- อนุญาตตัวไทย ตัวอังกฤษ ตัวเลข `.`, `_`, `-`
- เปลี่ยนได้สูงสุด 10 ครั้งต่อ 10 นาทีต่อ user
- username ซ้ำคืน HTTP `409 {"detail":"Username is already taken"}`

คืน envelope สำเร็จ `PROFILE_UPDATE_SUCCESS` พร้อม User

## 6.4 `POST /api/profile/login-history`

```json
{
  "token": "<access-jwt>"
}
```

คืน envelope โดย `data` เป็น array ล่าสุด 50 รายการ ไม่มี pagination:

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "ดึงประวัติการเข้าสู่ระบบสำเร็จ",
  "data": [
    {
      "id": "<uuid>",
      "provider": "password",
      "ip": "127.0.0.1",
      "user_agent": "Mozilla/5.0",
      "status": "success",
      "created_at": "2026-09-24T10:30:00"
    }
  ]
}
```

`provider` ที่พบ: `password`, `google`, `github`

`status` อาจเป็น `otp_required`, `success`, `success_device_bypass`

## 6.5 `POST /api/profile/download`

ใช้บันทึก event หลัง client ดาวน์โหลด report สำเร็จ

```json
{
  "token": "<access-jwt>",
  "file_name": "virustotal-<md5>.json",
  "tool": "virustotal",
  "md5": "<md5>"
}
```

ทุก field นอกจาก `token` เป็น optional

คืน:

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "บันทึกประวัติการดาวน์โหลดสำเร็จ",
  "data": null
}
```

## 6.6 `POST /api/profile/download-history`

```json
{
  "token": "<access-jwt>"
}
```

คืน envelope โดย `data` เป็น array ล่าสุด 50 รายการ ไม่มี pagination:

```json
{
  "success": true,
  "status": "LOGIN_SUCCESS",
  "message": "ดึงประวัติการดาวน์โหลดสำเร็จ",
  "data": [
    {
      "id": "<uuid>",
      "file_name": "virustotal-<md5>.json",
      "tool": "virustotal",
      "md5": "<md5>",
      "created_at": "2026-09-24T10:30:00"
    }
  ]
}
```

## 6.7 `POST /api/profile/avatar`

ใช้ `multipart/form-data`

| Field | Type | Required | ข้อจำกัด |
|---|---|---|---|
| `token` | text | ใช่ | access token |
| `file` | file | ใช่ | PNG, JPEG, WEBP |

กติกา:

- สูงสุด 5 MB
- กว้างและสูงไม่เกิน 4096 px
- server decode และ encode image ใหม่จริง ไม่เชื่อ MIME type จาก client
- อัปโหลดสูงสุด 10 ครั้งต่อ 10 นาที
- filename ใหม่เป็น random token ไม่ใช่ uid

คืน envelope `AVATAR_UPDATE_SUCCESS` พร้อม User ที่มี `avatar_url` ใหม่

Error ที่เป็น `HTTPException`:

| HTTP | Detail |
|---:|---|
| `400` | unsupported image, empty file หรือ dimension เกิน |
| `404` | ไม่พบ user |
| `413` | ไฟล์เกิน 5 MB |

## 6.8 `GET /api/profile/avatar/{file_name}`

ไม่ต้อง auth

```text
GET /api/profile/avatar/4f6d2a1c0b7d8e9f10a2b3c4d5e6f708.png
```

- คืน image binary
- filename ต้องเป็น random 32 hex + `.png`, `.jpg` หรือ `.webp`
- `Cache-Control: private, max-age=86400`
- ไม่พบหรือชื่อไม่ถูกต้องคืน `404`

---

## 7. Analysis API

## 7.1 `POST /api/analy/v1/generate-token`

```json
{
  "token": "<access-jwt>"
}
```

สร้างใหม่:

```json
{
  "success": true,
  "status": "TOKEN_CREATED",
  "message": "สร้างโทเค็นสำหรับอัปโหลดไฟล์สำเร็จ",
  "data": {
    "upload_token": "<upload-jwt>",
    "expires_in": 900
  }
}
```

ถ้ายังมี token เดิมจะคืน token เดิม:

```json
{
  "success": true,
  "status": "TOKEN_ALREADY_EXISTS",
  "message": "โทเค็นสำหรับอัปโหลดไฟล์ถูกสร้างสำเร็จ",
  "data": {
    "upload_token": "<same-upload-jwt>",
    "expires_in": 420
  }
}
```

Upload token ผูกกับ user ผ่าน Redis และใช้ซ้ำได้จน TTL หมด ไม่ได้ถูก consume หลัง upload

## 7.2 `POST /api/analy/v1/check-hash`

ใช้ตรวจก่อน upload เพื่อหลีกเลี่ยงส่งไฟล์ซ้ำ

```json
{
  "token": "<access-jwt>",
  "sha256": "<64-hex>",
  "file_name": "sample.apk",
  "file_size": 123456,
  "privacy": true
}
```

| Field | Required | กติกา |
|---|---|---|
| `token` | ใช่ | access token ไม่ใช่ upload token |
| `sha256` | ใช่ | normalize เป็น lowercase; ต้องเป็น 64 hex |
| `file_name` | ใช่ | ชื่อไฟล์ |
| `file_size` | ใช่ | `>= 0` |
| `privacy` | ไม่ | ค่าเริ่มต้น `true` = ส่วนตัว |

### ไม่พบงานเดิม

```json
{
  "success": true,
  "found": false
}
```

### พบงานเดิม

```json
{
  "success": true,
  "found": true,
  "task_id": "<uuid>",
  "status": "success",
  "md5": "<md5>",
  "sha256": "<sha256>",
  "filename": "sample.apk",
  "report": {
    "score": 82.3,
    "risk_level": "High",
    "virustotal_score": 100,
    "mobsf_score": 65.0,
    "cape_score": 78.5,
    "rampart_ai_score": {}
  }
}
```

- `found: true` หมายถึงผูก user กับ task เดิมแล้ว
- ถ้า `status` ยังไม่จบ ให้ poll `task_id` โดยไม่ upload
- ถ้า `status: success` ให้ใช้ `report` ที่คืนมาได้ทันที

### กำลัง dispatch

```json
{
  "success": true,
  "found": false,
  "status": "dispatching",
  "message": "Analysis dispatch is in progress for this file. Please upload as normal."
}
```

### พบ report เดิมที่ข้าม tool

```json
{
  "success": true,
  "found": true,
  "gap_filled": true,
  "task_id": "<new-task-id>",
  "status": "queued",
  "md5": "<md5>",
  "sha256": "<sha256>",
  "filename": "sample.apk",
  "message": "Prior analysis had gaps; re-running the missing tool(s)."
}
```

กรณีนี้ไม่ต้อง upload แต่ต้อง poll `task_id` ใหม่

### คำนวณ SHA-256 ฝั่ง browser

```ts
export async function sha256Hex(file: File): Promise<string> {
  const bytes = await file.arrayBuffer()
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")
}
```

ข้อควรระวัง: `file.arrayBuffer()` โหลดทั้งไฟล์เข้า memory การ hash ไฟล์ขนาดใกล้ 1 GB ด้วยวิธีนี้อาจทำให้ browser crash ควรข้าม precheck สำหรับไฟล์ขนาดใหญ่และ upload ตามปกติ

## 7.3 `POST /api/analy/v1/upload`

ใช้ `multipart/form-data`

| Field | ตำแหน่ง | Required | หมายเหตุ |
|---|---|---|---|
| `file` | form file | ใช่ | สูงสุด 1 GB, ห้ามว่าง |
| `privacy` | form boolean | ไม่ | ค่าเริ่มต้น `true` = ส่วนตัว |
| `token` | query หรือ form | ใช่ | upload token |

ใช้ query:

```text
POST /api/analy/v1/upload?token=<upload-jwt>
Content-Type: multipart/form-data
```

ใช้ form:

```text
POST /api/analy/v1/upload
Content-Type: multipart/form-data

file=<binary>&privacy=true&token=<upload-jwt>
```

ตัวอย่าง browser:

```ts
const form = new FormData()
form.append("file", file)
form.append("privacy", "true")
form.append("token", uploadToken)

await apiFetch("/api/analy/v1/upload", {
  method: "POST",
  body: form,
})
```

### ส่งงานใหม่

```json
{
  "success": true,
  "task_id": "<uuid>",
  "status": "queued",
  "md5": "<md5>",
  "sha256": "<sha256>",
  "filename": "sample.apk",
  "deduplicated": false,
  "queue_state": "dispatched"
}
```

### ใช้ task เดิม

```json
{
  "success": true,
  "task_id": "<existing-task-id>",
  "status": "success",
  "md5": "<md5>",
  "sha256": "<sha256>",
  "filename": "sample.apk",
  "deduplicated": true,
  "queue_state": "reused"
}
```

### Gap fill

```json
{
  "success": true,
  "task_id": "<new-task-id>",
  "status": "queued",
  "md5": "<md5>",
  "sha256": "<sha256>",
  "filename": "sample.apk",
  "deduplicated": false,
  "queue_state": "gap_filled"
}
```

### Error

| HTTP | Detail | การจัดการแนะนำ |
|---:|---|---|
| `400` | `File is empty.` | เลือกไฟล์ใหม่ |
| `401` | upload token ไม่ถูกต้อง/หมดอายุ/ไม่ตรง user | ขอ `generate-token` ใหม่ |
| `403` | account ถูก ban | แสดงสถานะบัญชี |
| `409` | กำลัง dispatch hash เดียวกัน | retry หลังสั้น ๆ |
| `413` | ไฟล์เกิน 1 GB | ลดขนาดไฟล์ |
| `422` | ไม่มี token | เพิ่ม query หรือ form field `token` |
| `503` | queue ใช้งานไม่ได้ | แจ้งระบบชั่วคราว แล้ว retry |
| `500` | ประมวลผลไฟล์ไม่สำเร็จ | ลองใหม่หรือแจ้ง error |

## 7.4 `POST /api/analy/v1/task_id`

```json
{
  "token": "<access-jwt>",
  "task_id": "<task-uuid>"
}
```

เจ้าของ task และ public task ดูได้ ส่วน `admin`/`master` ดู private task ของผู้ใช้อื่นได้โดยมี audit log

### กำลังประมวลผล

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "status": "processing",
  "message": "Analysis is not completed yet",
  "tool_notes": null,
  "progress": {
    "stage": "sandboxes",
    "message": "Waiting for sandbox reports",
    "updated_at": "2026-09-24T10:30:00+00:00",
    "tools": {
      "virustotal": {
        "status": "success",
        "score": 0
      },
      "mobsf": {
        "status": "processing"
      },
      "cape": {
        "status": "pending",
        "task_id": "<cape-task-id>"
      },
      "rampart_ai": {
        "status": "waiting"
      },
      "gemini": {
        "status": "waiting"
      }
    }
  }
}
```

`progress` เป็น optional และอาจไม่มี เพราะ Redis อาจไม่พร้อมหรือ worker ยังไม่ publish

### สำเร็จ

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "status": "success",
  "report": {
    "aid": "<uuid>",
    "rid": "<uuid>",
    "task_id": "<task-uuid>",
    "uid": "<uuid>",
    "privacy": true,
    "file_name": "sample.apk",
    "file_size": 123456,
    "file_hash": "<sha256>",
    "file_path": "temps_files/<sha256>.apk",
    "file_type": "apk",
    "tools": "virustotal,mobsf,cape,rampart_ai,gemini",
    "tool_notes": null,
    "md5": "<md5>",
    "status": "success",
    "deleted_at": null,
    "deleted_by": null,
    "created_at": "2026-09-24T10:30:00+00:00",
    "report_file_type": "apk",
    "virustotal_score": 0,
    "mobsf_score": 65.0,
    "cape_score": 78.5,
    "rampart_ai_score": {},
    "score": 82.3,
    "risk_level": "High",
    "recommendation": "...",
    "analysis_summary": "...",
    "risk_indicators": [],
    "gemini_recommendation": "...",
    "malware_signatures": [],
    "report_created_at": "2026-09-24T10:31:00+00:00"
  }
}
```

ค่า field บางตัวเป็น `null` ได้ เช่น score ของ tool ที่ถูก skip หรือ report ที่ยังไม่สร้าง

### ล้มเหลว

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "status": "failed",
  "message": "Analysis failed",
  "tool_notes": {
    "cape": "CAPE skipped after 3 failed attempts: ..."
  }
}
```

### ไม่พบ task

```json
{
  "success": false,
  "task_id": "<task-uuid>",
  "message": "TASK_NOT_FOUND"
}
```

### การ poll

- Terminal success: `success`
- Terminal failure: `failed`
- สถานะอื่นที่ไม่รู้จักควรถือว่ากำลังทำงาน
- Server cache response 3 วินาที
- แนะนำ poll ทุก 3-5 วินาที
- Task มี hard time limit 1 ชั่วโมง

## 7.5 `POST /api/analy/v1/report_target`

ดึง raw report ของ tool เดียว โดย schema ไม่อนุญาต field เพิ่ม

```json
{
  "token": "<access-jwt>",
  "task_id": "<task-uuid>",
  "tool": "virustotal"
}
```

`tool` ต้องเป็นหนึ่งใน:

- `virustotal`
- `mobsf`
- `cape`
- `rampartai`

ค่าเริ่มต้นคือ `virustotal`

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "status": "success",
  "tool": "virustotal",
  "report": {}
}
```

Raw JSON ขึ้นอยู่กับ provider/sandbox จึงไม่ควร hard-code schema ของ `report`

ไฟล์ไม่มี:

```json
{
  "success": false,
  "task_id": "<task-uuid>",
  "status": "success",
  "tool": "virustotal",
  "message": "REPORT_FILE_NOT_FOUND",
  "report": null
}
```

Task ยังไม่จบ:

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "status": "processing",
  "message": "Analysis is not completed yet"
}
```

## 7.6 `GET /api/analy/v1/download/report/{file_name}`

วิธีที่แนะนำ:

```http
GET /api/analy/v1/download/report/virustotal-<md5>.json
Authorization: Bearer <access-jwt>
```

วิธี fallback:

```text
GET /api/analy/v1/download/report/virustotal-<md5>.json?token=<access-jwt>
```

รูปแบบ `file_name`:

```regex
^(virustotal|mobsf|cape|rampartai)-([a-fA-F0-9]{32})\.json$
```

- คืนไฟล์ JSON
- เจ้าของและ public report ดาวน์โหลดได้
- admin/master ดาวน์โหลด private report ได้โดยมี audit log
- ควรใช้ Bearer header เพื่อหลีกเลี่ยงการส่ง token ใน URL/history/log
- เมื่อใช้ header ควรดาวน์โหลดด้วย `fetch` แล้วสร้าง Blob URL
- หลังดาวน์โหลดสำเร็จ เรียก `POST /api/profile/download` เพื่อบันทึกประวัติ

## 7.7 `POST /api/analy/v1/history`

ประวัติของ user จาก access token เท่านั้น ไม่มี target uid

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 10,
  "s": "sample",
  "status": "success",
  "file_type": "apk",
  "created_at": -1,
  "file_name": 0,
  "file_size": 0,
  "score": 0
}
```

| Field | Type | Default | กติกา |
|---|---|---:|---|
| `page` | integer | `1` | 1-10000 |
| `limit` | integer | `10` | 1-100 |
| `s` | string/null | `null` | ค้น file_name, md5, sha256; ยาวไม่เกิน 100 |
| `status` | string/null | `null` | `pending`, `processing`, `success`, `failed` |
| `file_type` | string/null | `null` | `[a-z0-9]{1,10}` |
| `created_at` | integer | `-1` | -1 desc, 0 ไม่ sort, 1 asc |
| `file_name` | integer | `0` | ทิศทางเดียวกัน |
| `file_size` | integer | `0` | ทิศทางเดียวกัน |
| `score` | integer | `0` | ทิศทางเดียวกัน |

เลือก sort ได้ไม่เกิน 2 field พร้อมกัน ไม่งั้น `422`

ตัวอย่างตั้ง sort filename asc, size desc:

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "created_at": 0,
  "file_name": 1,
  "file_size": -1,
  "score": 0
}
```

Response:

```json
{
  "success": true,
  "data": [
    {
      "aid": "<uuid>",
      "task_id": "<task-uuid>",
      "file_name": "sample.apk",
      "file_size": 123456,
      "file_type": "apk",
      "file_hash": "<sha256>",
      "tools": "virustotal,mobsf,cape,gemini",
      "status": "success",
      "md5": "<md5>",
      "privacy": true,
      "created_at": "2026-09-24T10:30:00+00:00",
      "report": {
        "score": 82.3,
        "rampart_score": 85.0,
        "risk_level": "High",
        "virustotal_score": 0,
        "mobsf_score": 65.0,
        "cape_score": 78.5,
        "rampart_ai_score": {}
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 1,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

## 7.8 `PATCH /api/analy/v1/{task_id}/privacy`

เฉพาะเจ้าของ task เท่านั้น

```json
{
  "token": "<access-jwt>",
  "privacy": false
}
```

```json
{
  "success": true,
  "task_id": "<task-uuid>",
  "privacy": false,
  "message": "อัปเดตความเป็นส่วนตัวของรายงานสำเร็จ"
}
```

---

## 8. Dashboard API

## 8.1 `POST /api/analy/v1/dashboard/summary`

```json
{
  "token": "<access-jwt>"
}
```

Response ไม่มี envelope:

```json
{
  "totalFiles": {
    "total": 100,
    "success": 80,
    "pending": 10,
    "failed": 10
  },
  "userFiles": {
    "total": 5,
    "success": 4,
    "pending": 1,
    "failed": 0
  },
  "totalUsers": 42,
  "topMalwareTypes": {
    "daily": [
      {
        "type": "Trojan",
        "count": 5
      }
    ],
    "monthly": [
      {
        "type": "Trojan",
        "count": 20
      }
    ]
  },
  "riskScores": [
    {
      "fileType": "apk",
      "riskScore": 65.5,
      "virustotalScore": 0.0,
      "mobsfScore": 60.0,
      "capeScore": null,
      "aiScore": null
    }
  ]
}
```

หมายเหตุ:

- `totalFiles` เป็นทั้งระบบ
- `userFiles` เป็นของผู้ใช้ปัจจุบัน
- `topMalwareTypes` คือข้อมูลทั้งระบบ
- `riskScores` เป็นค่าเฉลี่ยสูงสุด 5 file type
- soft-deleted files ถูกตัดออก

## 8.2 `POST /api/analy/v1/dashboard/recent-activities`

```json
{
  "token": "<access-jwt>"
}
```

คืน array 10 รายการโดยตรง ไม่มี envelope:

```json
[
  {
    "id": "<uuid>",
    "fileName": "sample.apk",
    "fileType": "apk",
    "status": "success",
    "timestamp": "2026-09-24 10:30:00"
  }
]
```

- `admin` เห็นกิจกรรมทุก user
- role อื่นเห็นเฉพาะของตัวเอง

## 8.3 `POST /api/analy/v1/dashboard/reports`

ต้องส่ง access token ใน body (ต้องล็อกอิน) คืนเฉพาะ analysis ที่ `privacy: false` (สาธารณะ) และยังไม่ถูกลบ

### Request

```json
{
  "page": 1,
  "limit": 10,
  "s": "sample",
  "status": "success",
  "file_type": "apk",
  "created_at": -1,
  "file_name": 0,
  "file_size": 0,
  "score": 0
}
```

กติกาเหมือน `/api/analy/v1/history` แต่ไม่มี `token`

Response:

```json
{
  "success": true,
  "data": [
    {
      "aid": "<uuid>",
      "task_id": "<task-uuid>",
      "file_name": "sample.apk",
      "file_size": 123456,
      "file_type": "apk",
      "file_hash": "<sha256>",
      "tools": "virustotal,mobsf,cape,gemini",
      "status": "success",
      "md5": "<md5>",
      "privacy": true,
      "created_at": "2026-09-24T10:30:00+00:00",
      "uploaded_by": {
        "username": "analyst01",
        "avatar_url": "/api/profile/avatar/<random-token>.png"
      },
      "report": {
        "score": 82.3,
        "rampart_score": 85.0,
        "risk_level": "High",
        "virustotal_score": 0,
        "mobsf_score": 65.0,
        "cape_score": 78.5,
        "rampart_ai_score": {}
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 1,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

---

## 9. Admin API

## 9.1 กติการ่วม

ทุก body ต้องมี:

```json
{
  "token": "<access-jwt>"
}
```

ทุก schema ของ admin ปฏิเสธ unknown field ด้วย `422`

List response ส่วนใหญ่ใช้:

```json
{
  "success": true,
  "data": [],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 0,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

โค้ดคืน `total_pages` อย่างน้อย 1 แม้ไม่มีข้อมูล จึงไม่ควรใช้ `total_pages === 0` เป็นเงื่อนไขว่าง

## 9.2 ผู้ใช้

### `POST /api/admin/users`

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "q": "analyst",
  "role": ["user", "admin"],
  "banned": false
}
```

| Field | Default | กติกา |
|---|---:|---|
| `page` | 1 | 1-10000 |
| `limit` | 20 | 1-100 |
| `q` | null | ค้น username/email ยาวไม่เกิน 100 |
| `role` | null | string หรือ array จาก `user`, `admin`, `master` |
| `banned` | null | true/false/null |

`data` แต่ละ item:

```json
{
  "uid": "<uuid>",
  "username": "analyst01",
  "email": "analyst@example.com",
  "avatar_url": null,
  "role": "user",
  "status": "active",
  "is_banned": false,
  "banned_at": null,
  "banned_reason": null,
  "banned_by": null,
  "created_at": "2026-09-24T10:30:00+00:00"
}
```

### `POST /api/admin/users/detail`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>"
}
```

คืน envelope `success: true` พร้อม User แบบเดียวกับรายการผู้ใช้

### `POST /api/admin/users/history`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>",
  "page": 1,
  "limit": 10,
  "s": null,
  "status": "success",
  "file_type": "apk",
  "created_at": -1,
  "file_name": 0,
  "file_size": 0,
  "score": 0
}
```

- แสดงทั้ง public/private ของ target
- ตัด soft-deleted ออก
- ตรวจสิทธิ์ตามเจ้าของไฟล์
- มี audit log
- item ประกอบด้วย `aid`, `task_id`, `file_name`, `file_size`, `file_type`, `file_hash`, `md5`, `tools`, `status`, `privacy`, `is_malicious`, `created_at`, `report`
- `report` มี `score`, `rampart_score`, `risk_level`, `virustotal_score`, `mobsf_score`, `cape_score`

### `POST /api/admin/users/login-history`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>",
  "page": 1,
  "limit": 20
}
```

คืน paginated login history โครงสร้างเดียวกับ profile login history

### `POST /api/admin/users/download-history`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>",
  "page": 1,
  "limit": 20
}
```

คืน paginated download history โครงสร้างเดียวกับ profile download history

## 9.3 จัดการผู้ใช้

### `POST /api/admin/users/ban`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>",
  "reason": "พบพฤติกรรมผิดปกติ"
}
```

เหตุผล 1-500 ตัวอักษร คืน `BAN_SUCCESS` พร้อม User

### `POST /api/admin/users/unban`

```json
{
  "token": "<access-jwt>",
  "target_uid": "<uuid>"
}
```

คืน `UNBAN_SUCCESS` พร้อม User

### `POST /api/admin/users/role`

ใช้ได้เฉพาะ `master`

```json
{
  "token": "<master-access-jwt>",
  "target_uid": "<uuid>",
  "new_role": "admin"
}
```

`new_role` อนุญาตเฉพาะ `user` หรือ `admin` ไม่สามารถตั้งเป็น `master` ผ่าน API

### `POST /api/admin/users/bulk-ban`

```json
{
  "token": "<access-jwt>",
  "target_uids": ["<uuid-1>", "<uuid-2>"],
  "reason": "Policy violation"
}
```

- 1-100 target
- ประมวลผลทีละ target
- target บางตัวอาจสำเร็จและบางตัว fail

```json
{
  "success": true,
  "data": {
    "succeeded": ["<uuid-1>"],
    "failed": [
      {
        "uid": "<uuid-2>",
        "reason": "..."
      }
    ]
  }
}
```

## 9.4 Admin dashboard

### `POST /api/admin/dashboard/summary`

```json
{
  "token": "<access-jwt>",
  "trend_days": 14
}
```

`trend_days` ต้องอยู่ระหว่าง 1-90

```json
{
  "success": true,
  "data": {
    "total_users": 100,
    "role_breakdown": {
      "user": 97,
      "admin": 2,
      "master": 1
    },
    "banned_count": 1,
    "total_analyses": 500,
    "malicious_count": 80,
    "upload_trend": [
      {
        "date": "2026-09-24",
        "count": 5
      }
    ],
    "status_breakdown": [
      {
        "status": "success",
        "count": 400
      }
    ],
    "risk_level_breakdown": [
      {
        "risk_level": "High",
        "count": 80
      }
    ],
    "file_type_breakdown": [
      {
        "file_type": "apk",
        "count": 400
      }
    ],
    "tool_usage": [
      {
        "tool": "gemini",
        "count": 450
      }
    ],
    "recent_actions": [
      {
        "log_id": "<uuid>",
        "actor_username": "admin01",
        "target_username": "analyst01",
        "action": "ban_user",
        "detail": "reason=Policy violation",
        "created_at": "2026-09-24T10:30:00+00:00"
      }
    ]
  }
}
```

`file_type_breakdown` แสดงสูงสุด 8 กลุ่ม กลุ่มที่เหลือรวมเป็น `other`

## 9.5 Audit logs

### `POST /api/admin/audit-logs`

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "actor_uid": "<uuid>",
  "action": "ban"
}
```

`actor_uid`, `action` เป็น optional

แต่ละ item:

```json
{
  "log_id": "<uuid>",
  "actor_uid": "<uuid>",
  "actor_username": "admin01",
  "target_uid": "<uuid>",
  "target_username": "analyst01",
  "action": "ban_user",
  "detail": "reason=Policy violation",
  "created_at": "2026-09-24T10:30:00+00:00"
}
```

## 9.6 ไฟล์และ report

### `POST /api/admin/files`

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "q": "sample",
  "status": "success",
  "file_type": "apk",
  "privacy": true
}
```

`status`: `pending`, `processing`, `success`, `failed`

แต่ละ item:

```json
{
  "aid": "<uuid>",
  "task_id": "<task-uuid>",
  "file_name": "sample.apk",
  "file_size": 123456,
  "file_type": "apk",
  "file_hash": "<sha256>",
  "md5": "<md5>",
  "tools": "virustotal,mobsf,cape,gemini",
  "status": "success",
  "privacy": true,
  "is_malicious": false,
  "created_at": "2026-09-24T10:30:00+00:00",
  "owner_uid": "<uuid>",
  "owner_username": "analyst01",
  "report": {
    "score": 82.3,
    "risk_level": "High",
    "virustotal_score": 0,
    "mobsf_score": 65.0,
    "cape_score": 78.5
  }
}
```

### `POST /api/admin/reports`

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "q": "sample",
  "risk_level": "High",
  "file_type": "apk"
}
```

`risk_level` filter ต้องเป็น `Low`, `Caution`, `High` หรือ `Critical`

Endpoint นี้คืนเฉพาะ analysis สถานะ `success` ที่มี report

### `POST /api/admin/files/delete`

```json
{
  "token": "<access-jwt>",
  "aid": "<analysis-uuid>",
  "reason": "Requested by owner"
}
```

คืน:

```json
{
  "success": true,
  "status": "DELETE_FILE_SUCCESS",
  "message": "ลบไฟล์สำเร็จ",
  "data": {
    "aid": "<analysis-uuid>",
    "deleted_at": "2026-09-24T10:30:00+00:00"
  }
}
```

เป็น soft delete ถ้าไม่มี Analysis row อื่นอ้างถึงไฟล์ ระบบจะ unlink ไฟล์ต้นฉบับ

### `POST /api/admin/files/bulk-delete`

```json
{
  "token": "<access-jwt>",
  "aids": ["<analysis-uuid-1>", "<analysis-uuid-2>"],
  "reason": "Malware retention policy"
}
```

- 1-100 `aid`
- คืน `succeeded: string[]`
- คืน `failed: { aid: string, reason: string }[]`

## 9.7 CSV export

ทั้งสาม endpoint ใช้ POST body `{ "token": "<access-jwt>" }` และคืน `text/csv` พร้อม `Content-Disposition: attachment`

### `POST /api/admin/export/users`

ไฟล์ `users.csv`

Header:

```csv
uid,username,email,role,status,is_banned,banned_reason,created_at
```

### `POST /api/admin/export/files`

ไฟล์ `files.csv` เฉพาะ row ที่ยังไม่ soft delete

```csv
aid,task_id,file_name,file_type,status,owner,score,risk_level,is_malicious,created_at
```

### `POST /api/admin/export/audit-logs`

ไฟล์ `audit_logs.csv` สูงสุด 5000 รายการล่าสุด

```csv
log_id,actor,target,action,detail,created_at
```

ตัวอย่างดาวน์โหลด โดยส่ง token ใน JSON body เท่านั้น:

```ts
const response = await fetch(`${API_BASE_URL}/api/admin/export/users`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ token: accessToken }),
})

if (!response.ok) throw new Error("Export failed")
```

## 9.8 Broadcast email

### `POST /api/admin/broadcast-email`

```json
{
  "token": "<access-jwt>",
  "subject": "System maintenance",
  "message": "The system will be unavailable tonight.",
  "target_role": "user"
}
```

| Field | Required | กติกา |
|---|---|---|
| `subject` | ใช่ | 1-200 ตัวอักษร |
| `message` | ใช่ | 1-5000 ตัวอักษร |
| `target_role` | ไม่ | `user`, `admin`, `master`; null คือทุก role |

```json
{
  "success": true,
  "data": {
    "sent": 42,
    "total_recipients": 45
  }
}
```

## 9.9 System health

### `POST /api/admin/system/health`

```json
{
  "token": "<access-jwt>"
}
```

```json
{
  "success": true,
  "data": {
    "overall_status": "degraded",
    "checked_at": "2026-09-24T10:30:00+00:00",
    "checks": [
      {
        "name": "postgresql",
        "status": "up",
        "latency_ms": 2.1,
        "detail": null
      },
      {
        "name": "redis",
        "status": "up",
        "latency_ms": 1.2,
        "detail": null
      },
      {
        "name": "celery_workers",
        "status": "up",
        "latency_ms": 15.0,
        "detail": "1 worker(s) online",
        "workers": [
          {
            "name": "worker@host",
            "active_tasks": 1,
            "reserved_tasks": 0
          }
        ]
      }
    ]
  }
}
```

Check ที่เป็นไปได้:

- `postgresql`
- `redis`
- `celery_workers`
- `mobsf`
- `cape`
- `rampart_ai`
- `disk_space`
- `memory`

Status ต่อ check: `up`, `degraded`, `down`, `unconfigured`

Overall: `up`, `degraded`, `down`

Health response cache 15 วินาที

## 9.10 Task queue

### `POST /api/admin/tasks`

```json
{
  "token": "<access-jwt>",
  "page": 1,
  "limit": 20,
  "status": "processing",
  "q": "sample"
}
```

ถ้าไม่ใส่ `status` จะแสดงเฉพาะ `dispatching`, `queued`, `processing`

แต่ละ item:

```json
{
  "aid": "<uuid>",
  "task_id": "<task-uuid>",
  "file_name": "sample.apk",
  "status": "processing",
  "tool_notes": null,
  "owner_username": "analyst01",
  "owner_uid": "<uuid>",
  "created_at": "2026-09-24T10:30:00+00:00",
  "age_seconds": 120
}
```

### `POST /api/admin/tasks/depth`

```json
{
  "token": "<access-jwt>"
}
```

```json
{
  "success": true,
  "data": {
    "active": 1,
    "reserved": 0,
    "scheduled": 0,
    "workers_online": 1
  }
}
```

หากตรวจ Celery ไม่ได้ อาจมี `error` ใน data

### `POST /api/admin/tasks/retry`

```json
{
  "token": "<access-jwt>",
  "task_id": "<task-uuid>"
}
```

```json
{
  "success": true,
  "message": "ส่ง task เข้าคิวใหม่แล้ว",
  "task_id": "<task-uuid>"
}
```

### `POST /api/admin/tasks/cancel`

```json
{
  "token": "<access-jwt>",
  "task_id": "<task-uuid>"
}
```

```json
{
  "success": true,
  "message": "ยกเลิก task แล้ว",
  "task_id": "<task-uuid>"
}
```

## 9.11 Rate limits

### `POST /api/admin/rate-limits`

```json
{
  "token": "<access-jwt>"
}
```

```json
{
  "success": true,
  "data": {
    "total_locked": 1,
    "groups": [
      {
        "pattern": "otp_lockout:login:*",
        "label": "OTP Lockout - Login",
        "count": 1,
        "entries": [
          {
            "key": "otp_lockout:login:<uid>",
            "identifier": "<uid>",
            "ttl_seconds": 120
          }
        ]
      }
    ]
  }
}
```

### `POST /api/admin/rate-limits/clear`

```json
{
  "token": "<access-jwt>",
  "key": "otp_lockout:login:<uid>"
}
```

`key` ยาว 1-300 ตัวอักษร และต้องขึ้นต้นด้วย `otp_lockout:` หรือ `ratelimit:` เท่านั้น

ผลลัพธ์:

```json
{
  "success": true,
  "message": "ปลดล็อกสำเร็จ"
}
```

---

## 10. Test Mode API

## 10.1 `GET /test`

คืน test console HTML

## 10.2 `GET /test/api/status`

```json
{
  "test_mode": true,
  "database": true,
  "redis": true,
  "user": "active"
}
```

`user`: `missing`, `active`, `inactive`, `conflicting`

## 10.3 `POST /test/api/user`

ไม่มี body

สร้างใหม่ได้ HTTP `201`:

```json
{
  "state": "created",
  "user": {
    "uid": "<uuid>",
    "username": "<configured-test-username>",
    "email": "<configured-test-email>",
    "role": "test",
    "status": "active"
  }
}
```

ถ้ามีอยู่แล้วหรือ reactivate คืน HTTP `200` ด้วย `state: existing` หรือ `reactivated`

## 10.4 `POST /test/api/token`

ต้องสร้าง test user ก่อน

```json
{
  "access_token": "<access-jwt>",
  "upload_token": "<upload-jwt>",
  "token_type": "bearer",
  "expires_in": 900
}
```

Access token ของ test mode มีอายุ 60 นาที ส่วน upload token มีอายุ 900 วินาที

## 10.5 `GET /test/api/analysis/{task_id}`

```json
{
  "task_id": "<task-uuid>",
  "database": {
    "status": "success",
    "tools": "virustotal,mobsf,cape,gemini",
    "md5": "<md5>",
    "file_name": "sample.apk",
    "file_type": "apk",
    "file_size": 123456,
    "file_hash": "<sha256>",
    "rid": "<uuid>",
    "is_malicious": false,
    "blocked_by": null,
    "created_at": "2026-09-24T10:30:00+00:00",
    "scores": {
      "virustotal": 0,
      "mobsf": 65,
      "cape": 78.5,
      "gemini": 82.3,
      "rampart_ai": 85
    },
    "assessment": {
      "risk_level": "High",
      "summary": "...",
      "recommendation": "...",
      "verdict": "...",
      "indicators": []
    }
  },
  "progress": {},
  "reports": {
    "virustotal": {
      "exists": true,
      "path": "reports/virustotal-<md5>.json",
      "size": 1234
    },
    "mobsf": {
      "exists": true,
      "path": "reports/mobsf-<md5>.json",
      "size": 1234
    },
    "cape": {
      "exists": false,
      "path": "reports/cape-<md5>.json",
      "size": null
    }
  }
}
```

---

## 11. Analysis lifecycle สำหรับ frontend

### ลำดับสถานะ

```text
dispatching → queued → processing → success
                              └──→ failed
```

`task_id` endpoint ใช้กับทุกสถานะ จนกว่าจะเป็น `success` หรือ `failed`

### Pipeline

1. VirusTotal
2. MobSF
3. RampartAI ทำงานเมื่อ MobSF สำเร็จ
4. CAPE
5. Gemini สังเคราะห์หลักฐานและสร้างคะแนน/ความเสี่ยง

นโยบาย retry-then-skip:

| Tool | Error attempts | Status polls ก่อน skip |
|---|---:|---:|
| VirusTotal | 3 | 10 |
| MobSF | 3 | 30 |
| CAPE | 3 | 40 |
| RampartAI | retry ผ่าน worker retry | ตาม worker retry |

หาก VirusTotal score = `100` ระบบข้าม MobSF, RampartAI และ CAPE แล้วใช้ Gemini กับหลักฐาน VirusTotal เท่านั้น

ข้อจำกัด:

- Upload สูงสุด 1 GB
- VirusTotal ข้ามไฟล์ที่ใหญ่กว่า 32 MB
- MobSF รองรับ `.apk`, `.ipa`, `.xapk`, `.jex`, `.dex`, `.apks`, `.aab`
- CAPE มี mapping สำหรับหลายชนิดไฟล์ ดู implementation ปัจจุบันก่อนแสดงปุ่ม upload ตาม extension
- Celery task hard limit 1 ชั่วโมง
- Progress Redis TTL 24 ชั่วโมง
- Tool อาจถูก skip โดยไม่ทำให้ task ล้มเหลว ตรวจ `tool_notes`

### Progress object

`progress` อาจมี stage:

- `worker`
- `virustotal`
- `sandboxes`
- `rampart_ai`
- `gemini`
- `complete`
- `failed`

`progress.tools` อาจมีเพียงบาง tool ตาม stage ปัจจุบัน จึงต้องใช้ optional chaining ใน frontend

---

## 12. รูปแบบข้อมูลที่ควรมีใน frontend

## 12.1 Pagination

```ts
type Pagination = {
  page: number
  limit: number
  total: number
  total_pages: number
  has_next: boolean
  has_prev: boolean
}
```

ใช้กับ:

- user history
- public reports
- admin users
- admin user history
- admin login/download history
- audit logs
- admin files
- admin reports
- admin tasks

## 12.2 User

```ts
type User = {
  uid: string
  username: string
  email: string
  avatar_url: string | null
  role: "user" | "admin" | "master"
  status: string
  created_at: string | null
}
```

Admin user เพิ่ม:

```ts
type AdminUser = User & {
  is_banned: boolean
  banned_at: string | null
  banned_reason: string | null
  banned_by: string | null
}
```

## 12.3 Analysis report

```ts
type AnalysisStatus =
  | "dispatching"
  | "queued"
  | "processing"
  | "success"
  | "failed"
  | "pending"
  | "analyzing"
  | (string & {})

type ReportSummary = {
  score: number | null
  rampart_score: number | null
  risk_level: string | null
  virustotal_score: number | null
  mobsf_score: number | null
  cape_score: number | null
  rampart_ai_score: Record<string, unknown> | null
}

type AnalysisHistoryItem = {
  aid: string
  task_id: string | null
  file_name: string | null
  file_size: number | null
  file_type: string | null
  file_hash: string | null
  md5: string | null
  tools: string | null
  status: AnalysisStatus | null
  privacy: boolean
  created_at: string | null
  report: ReportSummary | null
}
```

`rampart_score` เป็นคะแนนตัวเลข ส่วน `rampart_ai_score` เป็น raw prediction object ห้ามใช้ชื่อซ้ำกัน

Public report item เพิ่ม:

```ts
type PublicAnalysisHistoryItem = AnalysisHistoryItem & {
  uploaded_by: {
    username: string
    avatar_url: string | null
  } | null
}
```

## 12.4 Full report

```ts
type FullReport = {
  aid: string
  rid: string | null
  task_id: string | null
  uid: string
  privacy: boolean
  file_name: string | null
  file_size: number | null
  file_hash: string | null
  file_path: string | null
  file_type: string | null
  tools: string | null
  tool_notes: Record<string, string> | null
  md5: string | null
  status: string
  deleted_at: string | null
  deleted_by: string | null
  created_at: string | null
  report_file_type: string | null
  virustotal_score: number | null
  mobsf_score: number | null
  cape_score: number | null
  rampart_ai_score: Record<string, unknown> | null
  score: number | null
  risk_level: string | null
  recommendation: string | null
  analysis_summary: string | null
  risk_indicators: string[] | null
  gemini_recommendation: string | null
  malware_signatures: string[] | null
  report_created_at: string | null
}
```

---

## 13. Integration flow สำหรับเว็บ

## 13.1 Login flow

```text
หน้า login
  → POST /api/auth/login
  → ถ้า OTP_SENT แสดงช่อง OTP
  → POST /api/auth/login/confirm
  → เก็บ access_token, refresh_token, deiveToken
  → POST /api/profile เพื่อโหลด user
  → หน้า dashboard
```

Device bypass:

```text
POST /api/auth/login พร้อม header deviceToken
  → ถ้า bypass_otp=true ใช้ access_token/device_token ได้ทันที
  → ถ้าไม่ใช่ ทำ OTP flow
```

## 13.2 Upload flow

```text
เลือกไฟล์
  → ถ้าไฟล์เล็ก: คำนวณ SHA-256 และ POST /check-hash
  → ถ้า found=true: ใช้ task_id เดิม
  → ถ้า gap_filled=true: ใช้ task_id ใหม่
  → ถ้า found=false: POST /generate-token
  → POST /upload
  → เก็บ task_id
  → POST /task_id ทุก 3-5 วินาที
  → success: แสดง report
  → failed: แสดง message และ tool_notes
```

## 13.3 Error handling

Client ควรแยกเป็น:

1. Network error
2. HTTP `4xx/5xx`
3. `detail` error
4. Envelope `success: false`
5. Business success ที่มี `status` เป็นการกระทำสำเร็จ เช่น `BAN_SUCCESS`

ตัวอย่าง:

```ts
function extractApiError(body: unknown): string {
  if (typeof body !== "object" || body === null) return "Request failed"

  if ("message" in body) {
    return String((body as { message: unknown }).message)
  }

  if ("detail" in body) {
    const detail = (body as { detail: unknown }).detail
    if (typeof detail === "string") return detail
    if (Array.isArray(detail) && detail[0] && "msg" in detail[0]) {
      return String((detail[0] as { msg: unknown }).msg)
    }
  }

  return "Request failed"
}
```

## 13.4 Cache ที่อาจทำให้เห็นข้อมูลเก่า

| กลุ่ม | TTL |
|---|---:|
| task status | 3 วินาที |
| profile/history/dashboard/activity | 5 วินาที |
| admin list | 5 วินาที |
| admin dashboard | 20 วินาที |
| system health | 15 วินาที |
| admin rate-limit snapshot | 10 วินาที |

หลัง update privacy, ban, unban, role, delete หรือ upload ให้ invalidate/refetch list ที่เกี่ยวข้องใน frontend

---

## 14. ข้อควรระวังสำหรับ agent ที่นำเอกสารไปสร้าง frontend

1. ห้ามส่ง `Authorization` เป็นหลัก ต้องส่ง `token` ใน JSON body ตามเอกสาร
2. ห้ามใช้ `data.deviceToken` จาก login confirm; ชื่อจริงคือ `data.deiveToken`
3. ห้ามตั้ง `privacy: false` เมื่อหมายถึง public; ในระบบนี้ `true` คือ public
4. ห้ามส่ง access token ไป `/upload`; endpoint นี้ต้องการ upload token
5. Upload token ไม่ใช่ Bearer token และรับได้เฉพาะ query/form
6. `tools` เป็น comma-separated string ไม่ใช่ array
7. `rampart_score` เป็น number; `rampart_ai_score` เป็น object
8. Raw tool report ไม่มี schema เดียวกัน ต้อง defensive parse
9. Progress เป็น optional และแต่ละ stage อาจมี tool ไม่ครบ
10. `422` มักมาจาก validation ไม่ใช่ business error
11. บาง business error คืน HTTP `200` พร้อม `success: false`
12. `dashboard/summary` และ `dashboard/recent-activities` ไม่คืน envelope
13. Admin export ใช้ POST แต่ตอบ CSV ไม่ใช่ JSON
14. อย่า retry upload ซ้ำทันทีเมื่อได้ `409`; อาจมี dispatch ของ hash เดียวกันกำลังทำงาน
15. ไม่มี idempotency key แยกต่างหาก แต่ dedup ด้วย SHA-256 ทำให้การอัปโหลดเนื้อหาเดิมใช้ task เดิม
16. ไม่มี websocket สำหรับ progress; ใช้ polling
17. OAuth callback ใช้ query token; ควรแทนที่ session ฝั่ง frontend แล้วลบ token ออกจาก URL ตาม security policy ของแอป
18. ห้ามเปิด test mode ใน production

---

## 15. สรุปสถานะ API ที่ใช้บ่อย

```ts
const status = response.status

if (status === "queued" || status === "processing" || status === "dispatching") {
  showProgress(response.progress)
  scheduleNextPoll()
} else if (status === "success") {
  showReport(response.report)
} else if (status === "failed") {
  showFailure(response.message, response.tool_notes)
} else {
  showFailure("TASK_NOT_FOUND")
}
```

เอกสารนี้ครอบคลุม route ที่ประกาศใน `start_server.py` และ `routers/*.py` รวม 60 method/path declarations รวม route ระบบและ test mode โดย response ที่ไม่มี `response_model` อาจเปลี่ยน field เพิ่มภายหลังได้ จึงควรใช้ optional parsing และตรวจ `success` ทุกครั้ง
