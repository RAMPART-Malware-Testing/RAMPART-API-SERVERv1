import os
import platform
from dotenv import load_dotenv

load_dotenv()

print(f"\n[RAMPART-AI] Celery Worker Starter")
print(f"{'='*30}")
print(f"Redis Host: {os.getenv('REDIS_HOST', '127.0.0.1')}")
print(f"OS Platform: {platform.system()}")

if platform.system() == 'Windows':
    pool_type = "solo"
    print(f"Mode: Windows Detected -> Using 'solo' pool")
else:
    pool_type = "prefork" 
    print(f"Mode: Linux/Unix -> Using 'prefork' pool (Default)")

cmd = f"celery -A bgProcessing.celery_app worker --loglevel=info --pool={pool_type}"
print(f"\nExecuting: {cmd}\n")

os.system(cmd)