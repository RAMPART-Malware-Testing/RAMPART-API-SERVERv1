def FilterCAPE(full_report):
    filtered_data = {
        "malscore": full_report.get("malscore", 0),
        "signatures": [sig.get("description") for sig in full_report.get("signatures", [])],
        "network_destinations": list(set([h.get("ip") for h in full_report.get("network", {}).get("hosts", [])])),
        "top_behavioral_summary": {
            "files_written": full_report.get("behavior", {}).get("summary", {}).get("file_written", [])[:5],
            "regkeys_opened": full_report.get("behavior", {}).get("summary", {}).get("regkey_opened", [])[:5]
        },
        "signer": full_report.get("static", {}).get("pe_signature", {}).get("signer", "Unknown")
    }
    return filtered_data