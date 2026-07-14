# task_handlers.py
import json
import math
from pathlib import Path

from calling.CAPE import CAPEAnalyzer
from calling.MobSF import MobSFCall
from calling.VirusTotal import VirusToTalAPI

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
vt = VirusToTalAPI()

def get_virustotal_attributes(report: dict) -> dict:
    return report.get("data", {}).get("attributes", {})


def get_malicious_virustotal_results(report: dict) -> dict:
    attributes = get_virustotal_attributes(report)
    if attributes:
        return {
            engine: result
            for engine, result in attributes.get("last_analysis_results", {}).items()
            if result.get("category") == "malicious"
        }
    return {
        str(index): result
        for index, result in enumerate(report.get("threats_found", {}).get("malicious", []))
    }


def is_reportvt_complete(report: dict) -> bool:
    if not report:
        return False

    if get_malicious_virustotal_results(report):
        return True

    attributes = get_virustotal_attributes(report)
    if attributes:
        stats = attributes.get("last_analysis_stats", {})
        total_scanners = sum(value for value in stats.values() if isinstance(value, int))
    else:
        total_scanners = report.get("scan_summary", {}).get("total_scanners", 0)

    return total_scanners >= 10


def write_raw_virustotal_report(report: dict, report_path: str | Path) -> str:
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False)
    return str(path)

def handle_virustotal(
    file_path: str,
    md5: str,
    sha256: str,
    total_size: int,
    is_retry: bool = False,
    client: VirusToTalAPI | None = None,
    report_path: str | Path | None = None,
) -> dict:
    client = client or vt
    report_path = Path(report_path or Path("reports") / f"virustotal-{md5}.json")
    result = client.get_report_by_hash(sha256 or md5)

    if result.get("state") == "found":
        report = result.get("data") or {}
        if is_reportvt_complete(report):
            return {
                "status": True,
                "report_path": write_raw_virustotal_report(report, report_path),
            }
        return {"status": "pending", "report_path": str(report_path), "retry_in": 60}

    if result.get("state") != "missing":
        return {
            "status": "failed",
            "report_path": str(report_path),
            "error": str(result.get("error", "VirusTotal lookup failed")),
        }

    if total_size > VIRUSTOTAL_MAX_SIZE:
        return {
            "status": "failed",
            "report_path": str(report_path),
            "error": "File exceeds VirusTotal size limit",
        }

    if is_retry:
        return {"status": "pending", "report_path": str(report_path), "retry_in": 60}

    upload = client.upload_file(file_path=file_path)
    if upload.get("state") == "uploaded":
        if not upload.get("analysis_id"):
            return {
                "status": "failed",
                "report_path": str(report_path),
                "error": "VirusTotal upload response missing analysis ID",
            }
        return {"status": "pending", "report_path": str(report_path), "retry_in": 300}
    return {
        "status": "failed",
        "report_path": str(report_path),
        "error": str(upload.get("error", "VirusTotal upload failed")),
    }

def calculate_threat_scoreVT(report: dict | str | Path) -> int:
    if isinstance(report, dict):
        vt_data = report
    else:
        path = Path(report)
        if not path.exists():
            return 0
        try:
            with path.open("r", encoding="utf-8") as file:
                vt_data = json.load(file)
        except (OSError, json.JSONDecodeError):
            return 0

    if get_malicious_virustotal_results(vt_data):
        return 100

    attributes = get_virustotal_attributes(vt_data)
    if attributes:
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(value for value in stats.values() if isinstance(value, int))
        reputation = attributes.get("reputation", 0)
        sigma_rules = attributes.get("sigma_analysis_stats", {})
    else:
        scan_summary = vt_data.get("scan_summary", {})
        malicious = scan_summary.get("malicious_count", 0)
        total = scan_summary.get("total_scanners", 0)
        reputation = scan_summary.get("reputation", 0)
        sigma_rules = vt_data.get("security_analysis", {}).get("sigma_rules", {})

    sigma_critical = sigma_rules.get('critical', 0)
    sigma_high = sigma_rules.get('high', 0)

    base_score = min(((malicious / total) * 5) * 70, 70) if total > 0 else 0

    extra_score = 0
    if sigma_critical > 0:
        extra_score += 20
    elif sigma_high > 0:
        extra_score += 10
        
    if reputation < 0:
        extra_score += min(abs(reputation) * 2, 10)

    final_score = int(min(base_score + extra_score, 100))
    
    if malicious == 0 and sigma_critical == 0 and sigma_high == 0:
        return 0
        
    return final_score


def _clamp_score(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Score must be finite")
    return round(max(0.0, min(value, 100.0)), 2)


def calculate_mobsf_danger_score(report: dict) -> float | None:
    security_score = report.get("security_score")
    if security_score is None:
        return None
    try:
        return _clamp_score(100 - float(security_score))
    except (TypeError, ValueError):
        return None


def calculate_cape_danger_score(report: dict) -> float | None:
    malscore = report.get("score")
    if malscore is None:
        return None
    try:
        return _clamp_score(float(malscore) * 10)
    except (TypeError, ValueError):
        return None


def _write_report(reports_dir: Path, name: str, report: dict) -> str:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / name
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)


def handle_mobsf(
    file_path: str,
    md5: str,
    *,
    submitted: bool = False,
    client: MobSFCall | None = None,
    reports_dir: Path = Path("reports"),
) -> dict:
    client = client or MobSFCall()
    report = client.generate_json_report(md5)
    if report.get("success"):
        data = report.get("data") or {}
        return {
            "state": "complete",
            "report_path": _write_report(reports_dir, f"mobsf-{md5}.json", data),
        }
    if submitted:
        return {"state": "pending", "submitted": True, "retry_in": 30}

    upload = client.upload_file(file_path)
    if not upload.get("success"):
        message = str(upload.get("error", "MobSF upload failed"))
        if "not support" in message.lower() or "format" in message.lower():
            return {"state": "skipped", "error": message}
        return {"state": "error", "error": message}

    data = upload.get("data") or {}
    file_hash = data.get("hash") or md5
    scan = client.scan_uploaded_file(file_hash, timeout=10)
    if not scan.get("success"):
        return {"state": "error", "error": str(scan.get("error", "MobSF scan failed"))}
    return {"state": "pending", "submitted": True, "retry_in": 30}


def handle_cape(
    file_path: str,
    md5: str,
    *,
    task_id=None,
    client: CAPEAnalyzer | None = None,
    reports_dir: Path = Path("reports"),
) -> dict:
    client = client or CAPEAnalyzer()
    if task_id is None:
        existing = client.cheack_analyer(file_path)
        if isinstance(existing, dict) and existing.get("error"):
            return {"state": "error", "error": str(existing["error"])}
        if existing:
            task_id = existing[0].get("id")
            retry_in = 30
        else:
            created = client.create_file_task(file_path, machine="win10")
            if created.get("status") == "error" or not created.get("task_id"):
                return {"state": "error", "error": str(created.get("error", "CAPE submission failed"))}
            task_id = created["task_id"]
            retry_in = 60
        return {"state": "pending", "task_id": task_id, "retry_in": retry_in}

    status = client.get_task_status(task_id)
    state = status.get("data")
    if isinstance(state, dict):
        state = state.get("status")
    if state in {"failed_analysis", "error", "failed"}:
        return {"state": "error", "task_id": task_id, "error": f"CAPE analysis failed: {state}"}
    if state != "reported":
        return {"state": "pending", "task_id": task_id, "retry_in": 30}

    report = client.get_report(task_id, md5)
    if report.get("status") != "success":
        return {"state": "error", "task_id": task_id, "error": str(report.get("error", "CAPE report failed"))}
    data = report.get("data") or {}
    return {
        "state": "complete",
        "report_path": _write_report(reports_dir, f"cape-{md5}.json", data),
        "task_id": task_id,
    }
