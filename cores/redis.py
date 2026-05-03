import redis
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("HOST_MAIN", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5
    )

    redis_client.ping()
    print(f"[/] Connected to Redis successfully at {REDIS_HOST}:{REDIS_PORT}.")

    # redis_client.flushall()
    # 
    # all_keys = redis_client.keys("*")
    # print(f"Total keys found: {len(all_keys)}")
    # for key in all_keys:
    #     print(f"🔑 Key: {key}")
    # print("Scanning all keys...")
    # count = 0
    # for key in redis_client.scan_iter("*"):
    #     print(f"[{count}] Key: {key}")
    #     count += 1
    
except redis.exceptions.ConnectionError as err:
    print(f"[x] Redis connection error at {REDIS_HOST}:{REDIS_PORT}: {err}")
except redis.exceptions.AuthenticationError as err:
    print(f"[x] Redis authentication error: {err}")
except Exception as err:
    print(f"[x] An unexpected error occurred: {err}")