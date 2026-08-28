import re
import json

def normalize_attributes(attributes):
    """Normalize attributes to have consistent format"""
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
    """Extract and normalize JSON from text response"""
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
    

    