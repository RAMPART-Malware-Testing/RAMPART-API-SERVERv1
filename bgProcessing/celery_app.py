from celery import Celery
import os
from dotenv import load_dotenv
load_dotenv()

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
else:
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

# สร้าง Instance ของ Celery
# broker: ที่ฝากงาน (Redis)
# backend: ที่เก็บผลลัพธ์
celery_app = Celery(
    "malware_analyzer",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Bangkok",
    enable_utc=True,
    task_track_started=True,  # ติดตามสถานะเมื่อ task เริ่มทำงาน
    task_time_limit=3600,  # Timeout 1 ชั่วโมง
    result_expires=86400,  # เก็บผลลัพธ์ 24 ชั่วโมง
    imports=('bgProcessing.tasks',)  # Auto-discover tasks
)

try:
    from . import tasks
    print("[Celery] Tasks module imported successfully")
except ImportError as e:
    print(f"[Celery] Warning: Could not import tasks module: {e}")