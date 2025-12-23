import os
import platform
from dotenv import load_dotenv
load_dotenv()

print(f"\nRedis Configuration:")
print(f"  REDIS_HOST: {os.getenv('REDIS_HOST', '127.0.0.1')}")
print(f"  REDIS_PORT: {os.getenv('REDIS_PORT', '6379')}")
print(f"  REDIS_PASSWORD: {'***' if os.getenv('REDIS_PASSWORD') else 'None'}")

print(f"\nPlatform Information:")
print(f"  OS: {platform.system()}")
print(f"  Python: {platform.python_version()}")

if platform.system() == 'Windows':
    pool_type = "solo"
    print(f"  Pool: {pool_type} (Windows compatibility mode)")
else:
    pool_type = "prefork"
    print(f"  Pool: {pool_type}")

print(f"\nStarting Celery Worker with --pool={pool_type}...\n")
os.system(f"celery -A bgProcessing.celery_app worker --loglevel=info --pool={pool_type}")
