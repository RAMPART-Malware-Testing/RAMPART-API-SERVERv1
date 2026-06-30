import os
import json
import httpx
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleRequest

FCM_V1_URL = "https://fcm.googleapis.com/v1/projects/rampart-f25c5/messages:send"
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]


class FCMService:

    @staticmethod
    def _get_credentials():
        path = os.getenv("FCM_SERVICE_ACCOUNT_PATH")
        if not path or not os.path.isfile(path):
            raise RuntimeError(
                f"FCM_SERVICE_ACCOUNT_PATH is not set or file not found: {path}"
            )
        creds = service_account.Credentials.from_service_account_file(
            path, scopes=SCOPES
        )
        creds.refresh(GoogleRequest())
        return creds

    @staticmethod
    async def send_notification(
        token: str,
        title: str,
        body: str,
        data: dict | None = None,
    ) -> dict:
        creds = FCMService._get_credentials()
        headers = {
            "Authorization": f"Bearer {creds.token}",
            "Content-Type": "application/json",
        }

        message = {
            "token": token,
            "notification": {
                "title": title,
                "body": body,
            },
        }
        if data:
            message["data"] = {k: str(v) for k, v in data.items()}

        payload = {"message": message}

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(FCM_V1_URL, headers=headers, json=payload)
            result = resp.json()
            print(f"[FCM v1] Response ({resp.status_code}): {result}")
            return {
                "success": resp.status_code == 200,
                "fcm_response": result,
            }
