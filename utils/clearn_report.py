def clean_mobsf_report(raw_data):
    if not raw_data:
        return None
    
    cleaned = {
        "app_name": raw_data.get("app_name"),
        "package_name": raw_data.get("package_name"),
        "version_name": raw_data.get("version_name"),
        "security_score": raw_data.get("appsec",{"security_score":None}).get("security_score"),
        "permissions": [],
        "high_risk_components": []
    }

    if "permissions" in raw_data:
        for perm_name, details in raw_data["permissions"].items():
            if details.get("status") == "dangerous":
                cleaned["permissions"].append({
                    "name": perm_name,
                    "description": details.get("description")
                })

    if "code_analysis" in raw_data:
        for key, findings in raw_data["code_analysis"].items():
            if isinstance(findings, dict) and findings.get("metadata", {}).get("severity") == "high":
                 cleaned["high_risk_components"].append(key)

    
    return cleaned

def clean_virustotal_smart(raw_data):
    if not raw_data:
        return None
    
    attrs = raw_data.get("data", {}).get("attributes", {})
    androguard = attrs.get("androguard", {})
    
    cert = androguard.get("certificate", {}).get("Subject", {})
    signer = cert.get("O")
    
    stats = attrs.get("last_analysis_stats", {})
    
    malware_findings = []
    results = attrs.get("last_analysis_results", {})
    for engine, result in results.items():
        if result.get("category") == "malicious":
            malware_findings.append(f"{engine}: {result.get('result')}")

    perms_raw = androguard.get("permission_details", {})
    permissions = list(perms_raw.keys()) if perms_raw else []

    return {
        "app_identity": {
            "names": attrs.get("names", [])[:3],
            "package_name": androguard.get("Package"),
            "developer_signer": signer,
            "is_google_app": "Google" in str(signer)
        },
        "scan_summary": {
            "malicious_count": stats.get("malicious", 0),
            "total_scanners": sum(stats.values()) if stats else 0
        },
        "threats_found": malware_findings,
        "permissions": permissions
    }