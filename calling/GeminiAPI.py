import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
import json
import time
import re
from google.genai.errors import ServerError, ClientError

load_dotenv()

def normalize_attributes(attributes):
    normalized = []
    seen_keys = {}
    for attr in attributes:
        if not attr or ":" not in attr:
            continue
        key, value = attr.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "volume":
            value = re.sub(r'\s+', '', value) 
            value = value.replace('ML', 'ml').replace('มล.', 'ml').replace('G', 'g')
        if key == "pa":
            value = re.sub(r'PA\s+', 'PA', value)
        normalized_attr = f"{key}: {value}"
        if key not in seen_keys:
            seen_keys[key] = []
        if value not in seen_keys[key]:
            seen_keys[key].append(value)
            normalized.append(normalized_attr)
    return normalized

def extract_json(text):
    pattern_array = r"```(?:json)?\s*(\[.*?\])\s*```"
    pattern_object = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern_array, text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        match = re.search(pattern_object, text, re.DOTALL)
        if match:
            json_str = match.group(1)
        elif text.strip().startswith("[") or text.strip().startswith("{"):
            json_str = text.strip()
        else:
            return None
    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            for item in data:
                if "attributes" in item and isinstance(item["attributes"], list):
                    item["attributes"] = normalize_attributes(item["attributes"])
        elif isinstance(data, dict):
            if "attributes" in data and isinstance(data["attributes"], list):
                data["attributes"] = normalize_attributes(data["attributes"])
        return json.dumps(data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        return json_str
    
def system_prompt():
    return """
Role:
คุณคือ "AI Security Auditor" ที่ชาญฉลาด วิเคราะห์ความปลอดภัยของไฟล์ APK/Exe สำหรับเก็บลงฐานข้อมูล PostgreSQL หน้าที่ของคุณคือ **แยกแยะระหว่าง "มัลแวร์" และ "แอปดีที่ขอสิทธิ์เยอะ"** ให้ออก

Task:
วิเคราะห์ JSON Input และสรุปผลในรูปแบบ JSON ที่กระชับที่สุด โดยใช้ Logic คะแนนแบบ **"ยิ่งเยอะ ยิ่งปลอดภัย" (High Score = Safe)**

**Analysis Logic (ลำดับการคิด):**

1.  **Check 1: Famous App Context (กฎแอปยอดนิยม)**
    - ดู `package_name` หรือ `app_name` ว่าเป็นแอปดังระดับโลกหรือไม่ (เช่น Instagram, Facebook, TikTok, WhatsApp, Banking Apps)
    - **ถ้าใช่:** ให้ผ่อนปรนเรื่อง `api_dexloading`, `api_native_code`, หรือ `permissions` เยอะๆ (เพราะแอปพวกนี้ซับซ้อนและจำเป็นต้องใช้)
    - **การตัดสิน:** หากไม่พบ Signature มัลแวร์ร้ายแรง (เช่น Ransomware/Trojan จาก CAPE) -> ให้ถือว่า **"ปลอดภัย (Green)"** คะแนน 80-100
    - **คำแนะนำ:** "ใช้งานได้ปกติ แต่ควรตรวจสอบว่าดาวน์โหลดมาจาก Official Store (Play Store/App Store) เพื่อป้องกันเวอร์ชันดัดแปลง"

2.  **Check 2: Malware Indicators (กฎจับมัลแวร์)**
    - หาก **ไม่ใช่** แอปดังในข้อ 1 ให้ตรวจสอบ `code_behavior` อย่างเข้มงวด
    - **หักคะแนนหนัก (เหลือ 0-30):** ถ้าพบ `api_dexloading` (Dropper), `api_sms_call` (SMS Fraud) ในแอปที่ไม่ควรมี
    - **หักคะแนนปานกลาง (เหลือ 40-60):** ถ้าพบ `api_native_code` เยอะๆ หรือ Permission ขัดแย้งกับหน้าที่ (เช่น ไฟฉายขออ่านรายชื่อ)

3.  **Check 3: Clean App (กฎแอปทั่วไป)**
    - ถ้าไม่ใช่แอปดัง แต่ Permission น้อย และไม่พบ API อันตราย -> คะแนน 90-100

**Output Format (JSON Only - Clean Structure for DB):**
{
  "app_metadata": {
    "name": "ชื่อแอป",
    "package": "ชื่อแพ็กเกจ (เช่น com.instagram.android)",
    "type": "Android/Windows"
  },
  "security_assessment": {
    "score": 0-100, // (100 = ปลอดภัยที่สุด, 0 = อันตรายที่สุด)
    "risk_level": "Safe / Caution / High Risk", // (Safe=80-100, Caution=50-79, High Risk=0-49)
    "verdict_color": "green / yellow / red"
  },
  "user_recommendation": "คำแนะนำสั้นๆ กระชับ (เช่น 'ปลอดภัย ใช้งานได้ตามปกติ', 'ใช้งานได้ แต่ต้องโหลดจาก Store เท่านั้น', 'ห้ามติดตั้งเด็ดขาด')",
  "analysis_summary": "สรุปเหตุผลใน 1-2 ประโยค (เช่น 'เป็นแอป Official ที่มีความซับซ้อนสูง แต่ไม่พบภัยคุกคาม' หรือ 'พบพฤติกรรม Dropper แอบโหลดโค้ด')",
  "risk_indicators": [
    "ลิสต์เฉพาะจุดที่สำคัญจริงๆ ไม่เกิน 3-5 ข้อ",
    "เช่น 'มีการใช้ Dynamic Loading (ปกติสำหรับแอปนี้)'",
    "หรือ 'Permission สอดคล้องกับฟีเจอร์ของแอป'"
  ]
}
"""

class GeminiAPICall:
    def __init__(self):
        self.api_keys = self._load_api_keys()
        if len(self.api_keys)<=0:
            raise Exception("No Gemini API Key found. Please set GEMINI_API_KEY1 environment variable.")
        self.current_key_index = 0
        self.current_model_index = 0
        self.models = [
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-001",
            "gemini-2.5-flash-lite",
            "gemini-2.0-flash-lite",
            "gemini-2.0-flash-lite-001",
        ]
        self.current_model_index = 0
        self.model = self.models[self.current_model_index]
        self.AI = genai.Client(api_key=self.api_keys[self.current_key_index])
        self.max_retries = 3
        self.retry_delay = 2
        self.rate_limit_delay = 4 

    def _load_api_keys(self):
        keys = []
        i = 1
        while True:
            key = os.getenv(f"GEMINI_API_KEY{i}")
            if key:
                keys.append(key)
                i += 1
            else:
                break
        return keys

    def _switch_model(self):
        self.current_model_index = (self.current_model_index + 1) % len(self.models)
        self.model = self.models[self.current_model_index]
        print(f"Switch Model: {self.model}")

    def _switch_api_key(self):
        self.current_key_index = self.current_key_index+1
        self.current_api_key = self.api_keys[self.current_key_index]

        if self.current_api_key is None:
            self.current_key_index = 0

        self.AI = genai.Client(api_key=self.current_api_key)

        self.current_model_index = 0
        self.model = self.models[self.current_model_index]

        print(f"Switch API Key : {self.current_key_index + 1} Start Model: {self.model}")

    def _print_usage(self, res):
        print('*'*100)
        if res.usage_metadata:
            print(f"Model: {self.model}")
            print(f"Prompt Tokens: {res.usage_metadata.prompt_token_count}")
            print(f"Candidates Tokens: {res.usage_metadata.candidates_token_count}")
            print(f"Total Tokens: {res.usage_metadata.total_token_count}")
        else:
            print("No usage metadata found.")
        print('*'*100)

    def AnalysisGemini(self, content):
        models_tried_in_current_key = 0
        keys_tried = 0
        max_keys = len(self.api_keys)

        while keys_tried < max_keys:
            retry_count = 0

            while retry_count < self.max_retries:
                try:
                    print(f"[API Key #{self.current_key_index + 1}] Use Model: {self.model} (Round {retry_count + 1}/{self.max_retries})")

                    res = self.AI.models.generate_content(
                        model=self.model,
                        contents=str(f"นี่คือข้อมูล Report ที่ต้องวิเคราะห์:{json.dumps(content)}"),
                        config=types.GenerateContentConfig(system_instruction=system_prompt()),
                    )
                    self._print_usage(res)
                    response = extract_json(res.text)
                    print(f"Analysis successfully! By: {self.model} (API Key #{self.current_key_index + 1})")
                    time.sleep(self.rate_limit_delay)
                    return response
                except ServerError as e:
                    error_msg = str(e)
                    print(f"ServerError: {error_msg}")
                    if "503" in error_msg or "overloaded" in error_msg.lower():
                        retry_count += 1
                        if retry_count < self.max_retries:
                            retry_seconds = None
                            try:
                                match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                                if match:
                                    retry_seconds = float(match.group(1))
                            except:
                                pass
                            wait_time = retry_seconds if retry_seconds else (self.retry_delay * retry_count)
                            print(f"Wait {wait_time}s before retrying...")
                            time.sleep(wait_time)
                        else:
                            print(f"Model {self.model} Max round {self.max_retries}")
                            break
                    else:
                        print(f"error : {error_msg}")
                        break

                except ClientError as e:
                    error_msg = str(e)
                    print(f"ClientError: {error_msg}")
                    if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
                        retry_seconds = None
                        try:
                            match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                            if match:
                                retry_seconds = float(match.group(1))
                        except:
                            pass
                        print(f"Model {self.model} quota exceeded. Switching to next model...")
                        if retry_seconds:
                            print(f"Suggested retry delay: {retry_seconds}s")
                            wait_time = min(retry_seconds, 20) 
                            print(f"Waiting {wait_time}s before switching model...")
                            time.sleep(wait_time)
                        else:
                            print(f"Waiting 5s before switching model...")
                            time.sleep(5)
                        break 
                    else:
                        print(f"Non-quota ClientError, stopping...")
                        break

                except Exception as e:
                    print(f"Unexpected Error: {type(e).__name__}: {str(e)}")
                    retry_count += 1
                    if retry_count < self.max_retries:
                        wait_time = self.retry_delay * retry_count
                        print(f"Wait {wait_time} secound Tey again...")
                        time.sleep(wait_time)
                    else:
                        break
            models_tried_in_current_key += 1
            if models_tried_in_current_key >= len(self.models):
                keys_tried += 1
                if keys_tried < max_keys:
                    print("="*100)
                    print(f"All models in API Key #{self.current_key_index + 1} exhausted. Switching to next API Key...")
                    print("="*100)
                    self._switch_api_key()
                    models_tried_in_current_key = 0
                else:
                    break
            else:
                self._switch_model()
        error_response = {
            "error": "All API keys and models failed",
            "reason": f"Tried {len(self.api_keys)} API key(s) with {len(self.models)} model(s) each",
            "api_keys_count": len(self.api_keys),
            "models_tried": self.models,
            "suggestion": "Please check your API keys, network connection, or try again later."
        }
        print(f"Failed all API keys and models: {json.dumps(error_response, ensure_ascii=False)}")
        return error_response

Gemini = None
def GeminiAPI():
    global Gemini
    if Gemini is None:
        Gemini = GeminiAPICall()
    return Gemini