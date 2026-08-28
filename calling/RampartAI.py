"""Client for the RampartAI malware-probability classifier.

This is a small internal model that only understands the shape of a MobSF
JSON report (see README/predict endpoint docs: "Upload a MobSF JSON report
and get malware probability."). It is intentionally NOT a general-purpose
classifier - it is only ever called with a report that MobSF itself already
produced, never with the raw uploaded file.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

class RampartAICall:
    def __init__(self):
        self.base_url = os.getenv("RAMPARTAI_URL", "").rstrip("/")

    def predict(self, mobsf_report_path: str) -> dict:
        if not self.base_url:
            return {"success": False, "error": "RAMPARTAI_URL is not configured"}
        if not os.path.exists(mobsf_report_path):
            return {"success": False, "error": f"File not found: {mobsf_report_path}"}

        url = f"{self.base_url}/predict"
        try:
            with open(mobsf_report_path, "rb") as file:
                files = {
                    "file": (
                        os.path.basename(mobsf_report_path),
                        file,
                        "application/json",
                    )
                }
                response = requests.post(url, files=files, timeout=60)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            return {
                "success": False,
                "error": f"Error {response.status_code}: {response.text}",
            }
        except requests.exceptions.RequestException as error:
            return {"success": False, "error": f"Request failed: {error}"}
        except Exception as error:
            return {"success": False, "error": str(error)}
