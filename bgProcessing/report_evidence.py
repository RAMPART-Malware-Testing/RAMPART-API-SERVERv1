import json
from pathlib import Path


MAX_FINDINGS = 10
MAX_TEXT = 240


def _read(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"Report must be a JSON object: {path}")
    return data


def _text(value) -> str | None:
    if value is None:
        return None
    return " ".join(str(value).split())[:MAX_TEXT]


def extract_virustotal_evidence(report: dict) -> dict:
    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})
    malicious = [
        {"engine": engine, "result": _text(result.get("result"))}
        for engine, result in results.items()
        if result.get("category") == "malicious"
    ][:MAX_FINDINGS]
    return {
        "status": "complete",
        "identity": {
            "name": _text(attributes.get("meaningful_name")),
            "type": _text(attributes.get("type_description")),
            "size": attributes.get("size"),
            "md5": attributes.get("md5"),
            "sha256": attributes.get("sha256"),
        },
        "stats": {
            key: stats.get(key, 0)
            for key in (
                "malicious", "suspicious", "undetected", "harmless", "timeout",
                "confirmed-timeout", "failure", "type-unsupported",
            )
        },
        "reputation": attributes.get("reputation", 0),
        "malicious_detections": malicious,
        "sigma_stats": attributes.get("sigma_analysis_stats") or {},
    }


def extract_mobsf_evidence(report: dict) -> dict:
    appsec = report.get("appsec") or {}
    security_score = appsec.get("security_score")
    try:
        danger_score = round(max(0.0, min(100 - float(security_score), 100.0)), 2)
    except (TypeError, ValueError):
        danger_score = None

    def findings(level: str) -> list[dict]:
        values = appsec.get(level) or []
        return [
            {
                "title": _text(item.get("title")),
                "section": _text(item.get("section")),
                "description": _text(item.get("description")),
            }
            for item in values[:MAX_FINDINGS]
            if isinstance(item, dict)
        ]

    permissions = report.get("permissions") or {}
    dangerous_permissions = [
        name
        for name, details in permissions.items()
        if isinstance(details, dict) and "dangerous" in str(details.get("status", "")).lower()
    ][:MAX_FINDINGS]
    return {
        "status": "complete",
        "identity": {
            "app_name": _text(report.get("app_name")),
            "package_name": _text(report.get("package_name")),
            "app_type": _text(report.get("app_type")),
            "version": _text(report.get("version_name")),
            "md5": report.get("md5"),
            "sha256": report.get("sha256"),
        },
        "security_score": security_score,
        "danger_score": danger_score,
        "finding_counts": {
            "high": len(appsec.get("high") or []),
            "warning": len(appsec.get("warning") or []),
            "info": len(appsec.get("info") or []),
        },
        "high_findings": findings("high"),
        "warning_findings": findings("warning")[:5],
        "dangerous_permissions": dangerous_permissions,
        "exported_count": report.get("exported_count"),
        "average_cvss": report.get("average_cvss"),
        "certificate_status": _text((report.get("certificate_analysis") or {}).get("certificate_status")),
    }


def extract_cape_evidence(report: dict) -> dict:
    malscore = report.get("malscore")
    try:
        danger_score = round(max(0.0, min(float(malscore) * 10, 100.0)), 2)
    except (TypeError, ValueError):
        danger_score = None
    signatures = sorted(
        (item for item in report.get("signatures") or [] if isinstance(item, dict)),
        key=lambda item: item.get("severity", 0),
        reverse=True,
    )
    target = report.get("target") or {}
    target_file = target.get("file") if isinstance(target.get("file"), dict) else target
    return {
        "status": "complete",
        "identity": {
            "name": _text(target_file.get("name")),
            "type": _text(target_file.get("type")),
            "size": target_file.get("size"),
            "md5": target_file.get("md5"),
            "sha256": target_file.get("sha256"),
        },
        "malscore": malscore,
        "danger_score": danger_score,
        "malstatus": _text(report.get("malstatus")),
        "analysis_timeout": bool((report.get("info") or {}).get("timeout")),
        "duration_seconds": (report.get("info") or {}).get("duration"),
        "signature_count": len(signatures),
        "top_signatures": [
            {
                "name": _text(item.get("name")),
                "severity": item.get("severity"),
                "description": _text(item.get("description")),
            }
            for item in signatures[:MAX_FINDINGS]
        ],
        "payload_count": len((report.get("CAPE") or {}).get("payloads") or []),
        "dropped_file_count": len(report.get("dropped") or []),
        "network_counts": {
            key: len((report.get("network") or {}).get(key) or [])
            for key in ("http", "dns", "hosts", "tcp", "udp")
        },
        "ttps": [
            ttp
            for group in (report.get("ttps") or [])[:MAX_FINDINGS]
            if isinstance(group, dict)
            for ttp in (group.get("ttps") or [])[:3]
        ],
    }


def build_gemini_evidence(
    virustotal_report_path: str | Path,
    mobsf_report_path: str | Path | None,
    cape_report_path: str | Path | None,
) -> dict:
    return {
        "schema_version": 1,
        "score_semantics": "All scores use 0=safe/no observed danger and 100=maximum observed danger.",
        "virustotal": extract_virustotal_evidence(_read(virustotal_report_path)),
        "mobsf": (
            extract_mobsf_evidence(_read(mobsf_report_path))
            if mobsf_report_path else {"status": "not_available"}
        ),
        "cape": (
            extract_cape_evidence(_read(cape_report_path))
            if cape_report_path else {"status": "not_available"}
        ),
    }
