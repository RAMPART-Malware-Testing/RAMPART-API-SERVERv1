import json
import math
import re
from collections import Counter
from pathlib import Path

from calling.CAPE import CAPEAnalyzer
from calling.MobSF import MobSFCall
from calling.RampartAI import RampartAICall
from calling.VirusTotal import VirusToTalAPI

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
MOBSF_SUPPORTED_EXTS = {".apk", ".ipa", ".xapk", ".jex", ".dex", ".apks", ".aab"}
CAPE_PACKAGE_MAP = {
    ".apk": "apk",
    ".xapk": "apk",
    ".dex": "android",
    ".jex": "android",
    ".exe": "exe",
    ".scr": "exe",
    ".com": "exe",
    ".dll": "dll",
    ".cpl": "dll",
    ".msi": "msi",
    ".msp": "msi",
    ".cab": "emulation",
    ".zip": "emulation",
    ".rar": "emulation",
    ".7z": "7z",
    ".tar": "emulation",
    ".gz": "emulation",
    ".gzip": "gzip",
    ".tgz": "emulation",
    ".bz2": "emulation",
    ".iso": "emulation",
    ".doc": "doc",
    ".docm": "docm",
    ".docx": "docx",
    ".dotm": "dotm",
    ".dotx": "dotx",
    ".rtf": "rtf",
    ".mht": "mht",
    ".sway": "sway",
    ".wsf": "generic",
    ".vsdx": "generic",
    ".xls": "xls",
    ".xlsb": "xlsb",
    ".xlsm": "xlsm",
    ".xlsx": "xlsx",
    ".xltm": "xlsm",
    ".xltx": "xlsm",
    ".ppt": "ppt",
    ".ppam": "ppt",
    ".ppa": "ppt",
    ".pps": "ppt",
    ".ppsm": "ppt",
    ".ppsx": "ppt",
    ".pptm": "ppt",
    ".pptx": "pptx",
    ".pot": "ppt",
    ".potm": "ppt",
    ".potx": "ppt",
    ".pub": "pub",
    ".pdf": "pdf",
    ".js": "js",
    ".jsx": "js",
    ".hta": "hta",
    ".html": "url",
    ".htm": "url",
    ".url": "http_url",
    ".vbs": "vbs",
    ".py": "python",
    ".ps1": "powershell",
    ".sh": "sh",
    ".jar": "jar",
    ".java": "java",
    ".msg": "msg",
    ".eml": "msg",
    ".tnef": "tnef",
    ".lnk": "lnk",
    ".elf": "elf",
    ".swf": "generic",
}
vt = VirusToTalAPI()

GENERIC_SIGNATURE_TOKENS = {
    "trojan", "backdoor", "worm", "virus", "malware", "generic", "variant", "gen",
    "agent", "win32", "win64", "w32", "w64", "msil", "heur", "heuristic", "suspicious",
    "likely", "possible", "riskware", "hacktool", "pua", "unwanted", "software",
    "downloader", "dropper", "exploit", "ransom", "ransomware", "spyware", "adware",
    "miner", "coinminer", "rootkit", "pws", "stealer", "banker", "fake", "misc",
    "threat", "detected", "blocked", "part", "start", "auto", "file", "script",
    "javascript", "python", "android", "linux", "osx", "macos", "email", "html",
    "php", "macro", "office", "bank", "crypt", "inject", "injector", "packed",
    "shell", "code", "multi", "genericml", "susp", "mal", "troj", "http", "https",
}

MALWARE_CATEGORY_TOKENS = {
    "trojan", "backdoor", "worm", "virus", "ransomware", "adware", "spyware",
    "rootkit", "miner", "coinminer", "downloader", "dropper", "hacktool", "pua",
    "riskware", "banker", "stealer", "keylogger", "botnet", "exploit",
}

CATEGORY_ALIASES = {"ransom": "ransomware", "trojangeneric": "trojan"}

def _title_token(token: str) -> str:
    if any(character.isupper() for character in token[1:]):
        return token
    return token[:1].upper() + token[1:]

def virustotal_threat_label(report: dict) -> str | None:
    attributes = get_virustotal_attributes(report) or {}
    classification = attributes.get("popular_threat_classification") or {}
    label = classification.get("suggested_threat_label")
    if not label:
        categories = [
            item for item in (classification.get("popular_threat_category") or [])
            if isinstance(item, dict) and item.get("value")
        ]
        categories.sort(key=lambda item: item.get("count") or 0, reverse=True)
        label = categories[0]["value"] if categories else None
    if not label:
        return None
    primary = str(label).split("/")[0].strip()
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", primary) if part]
    if not parts:
        return None
    return ".".join(_title_token(part) for part in parts[:3])

def malware_family_from_signatures(signatures: list[str] | None) -> str | None:
    families: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    display: dict[str, str] = {}
    for entry in signatures or []:
        text = str(entry).split(":", 1)[-1]
        for token in re.findall(r"[A-Za-z]{4,}", text):
            lowered = token.lower()
            if lowered in GENERIC_SIGNATURE_TOKENS:
                if lowered in MALWARE_CATEGORY_TOKENS:
                    categories[lowered] += 1
                continue
            families[lowered] += 1
            display.setdefault(lowered, token)
    if families:
        return _title_token(display[families.most_common(1)[0][0]])
    if categories:
        token = categories.most_common(1)[0][0]
        return _title_token(CATEGORY_ALIASES.get(token, token))
    return None

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

def virustotal_detection_counts(report: dict | str | Path) -> tuple[int, int] | None:
    if isinstance(report, dict):
        data = report
    else:
        try:
            with Path(report).open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            return None
    attributes = get_virustotal_attributes(data) or {}
    stats = attributes.get("last_analysis_stats") or {}
    if not stats:
        return None
    total = sum(int(value or 0) for value in stats.values())
    return len(get_malicious_virustotal_results(data)), total

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
    enable_hash_check: bool = True,
) -> dict:
    client = client or vt
    report_path = Path(report_path or Path("reports") / f"virustotal-{md5}.json")
    
    if not enable_hash_check:
        return {
            "status": "skipped",
            "report_path": str(report_path),
            "error": "VirusTotal hash check disabled",
        }
    
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
            "status": "skipped",
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
    return 0

def _clamp_score(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Score must be finite")
    return round(max(0.0, min(value, 100.0)), 2)

def calculate_mobsf_danger_score(report: dict) -> float | None:
    security_score = report.get("appsec", {}).get("security_score")
    if security_score is None:
        security_score = report.get("security_score")
    if security_score is None:
        return None
    try:
        return _clamp_score(100 - float(security_score))
    except (TypeError, ValueError):
        return None

CAPE_NATIVE_MAX_SCORE = 10.0
CAPE_FAILED_STATES = {"failed", "failed_analysis", "failed_reporting", "failed_processing", "error"}
CAPE_BLOCKED_LAUNCH_MARKERS = (
    "error_virus_infected",
    "contains a virus or potentially unwanted software",
    "unable to execute the initial process",
)
CAPE_PRIVILEGE_LAUNCH_MARKERS = ("(error: 740)", "(error:740)")

# Detections a static loader raised before the sample could be instrumented. These
# describe the file itself, so they hold even when the sandbox never ran it.
CAPE_STATIC_MALWARE_SIGNATURES = {
    "binary_yara": 3,
    "procmem_yara": 3,
    "static_pe_anomaly": 2,
    "pe_compile_timestomping": 2,
    "packer_entropy": 2,
    "packer_unknown_pe_section_name": 1,
    "antianalysis_tls_section": 1,
    "contains_pe_overlay": 1,
    "dropper": 2,
    "deletes_executed_files": 2,
}
CAPE_STATIC_SCORE_PER_POINT = 9

# A run the sandbox refused to start still carries file-intrinsic evidence. Even a
# single such indicator means the sample is not proven clean, so the floor never
# reads as "safe" once anything was found.
CAPE_STATIC_FLOOR_MINIMUM = 30

# A YARA rule that names a malware family, not just "suspicious/indicator", is close
# to a detection on its own.
CAPE_YARA_FAMILY_TOKENS = (
    "ransomware", "ransom", "trojan", "backdoor", "worm", "keylogger", "stealer",
    "rootkit", "miner", "coinminer", "botnet", "dropper", "downloader", "spyware",
    "credential", "mimikatz", "cobaltstrike", "metasploit", "shellcode",
)
CAPE_YARA_FAMILY_POINTS = 4

# Build paths and identifiers leak what the sample was built from. These are the
# strongest per-file hints available when the sandbox never ran anything: a UAC
# bypass kit or a remote-access-trojan project tree is not something a benign
# installer ships in its debug directory.
CAPE_PDB_STRONG_TOKENS = (
    "uac-bypass", "uacbypass", "byeintegrity", "fodhelper", "eventvwr", "sdclt",
    "computerdefaults", "slui", "wsreset", "pcaPayload".lower(),
    "mimikatz", "cobaltstrike", "meterpreter", "metasploit", "shellcode",
    "keylogger", "stealer", "ransomware", "injector", "injection", "exploit",
)
# Deliberately excludes generic build-artifact words such as "stub": compiler and
# installer scaffolding produces those, and a weak token alone already grants the
# 30-point floor, which must stay rare enough to mean something.
CAPE_PDB_WEAK_TOKENS = (
    "rats", "stealer", "keylogger", "botnet", "panel", "crypter",
    "malware", "backdoor", "trojan", "worm", "grabber",
    "hacktool", "bypass", "elevate",
)
CAPE_PDB_STRONG_POINTS = 4
CAPE_PDB_WEAK_POINTS = 3

# Process-manipulation APIs in a binary the sandbox blocked. Imports alone are not
# proof - a launcher legitimately maps and terminates processes - so this only counts
# when the binary also looks like something that was built to be hidden (packing,
# obfuscation, timestomping) or when the import set is wide enough to be an injector.
CAPE_INJECTION_IMPORTS = {
    "writeprocessmemory", "readprocessmemory", "virtualallocex", "virtualprotectex",
    "createremotethread", "ntunmapviewofsection", "queueuserapc",
    "setwindowshookexa", "setwindowshookexw", "openprocess",
    "createtoolhelp32snapshot", "process32firstw", "process32nextw",
    "mapviewoffile", "unmapviewoffile", "createprocessw", "createprocessa",
    "terminateprocess", "shellexecutew", "winexec", "urldownloadtofilew",
    "urldownloadtofilea", "internetopenurla",
}
CAPE_INJECTION_IMPORT_POINTS = 3
CAPE_INJECTION_IMPORTS_THRESHOLD = 5
# Import names that only make sense for code that touches another process's memory.
CAPE_STRONG_INJECTION_IMPORTS = {
    "writeprocessmemory", "readprocessmemory", "virtualallocex", "virtualprotectex",
    "createremotethread", "ntunmapviewofsection", "queueuserapc",
    "setwindowshookexa", "setwindowshookexw",
}
CAPE_CONCEALMENT_SIGNATURES = {
    "packer_entropy", "packer_unknown_pe_section_name", "binary_yara",
    "procmem_yara", "pe_compile_timestomping", "contains_pe_overlay",
    "antianalysis_tls_section", "static_pe_anomaly",
}

def _cape_pe_metadata(target_file: dict) -> dict:
    pe = target_file.get("pe")
    return pe if isinstance(pe, dict) else {}

def _cape_imported_names(pe: dict) -> list[str]:
    imports = pe.get("imports")
    names: list[str] = []
    if isinstance(imports, dict):
        groups = imports.values()
    elif isinstance(imports, list):
        groups = imports
    else:
        return names
    for group in groups:
        entries = group.get("imports") if isinstance(group, dict) else group
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                names.append(str(entry["name"]))
            elif isinstance(entry, str):
                names.append(entry)
    return names

def cape_pe_indicators(target_file: dict, concealed: bool = False) -> dict:
    """File-intrinsic PE hints that do not need the sample to have executed.

    `concealed` says the file also carries packing/obfuscation signals; ordinary
    launchers map and terminate processes openly, so the injection-import signal only
    counts for a binary that is trying not to be read.
    """
    pe = _cape_pe_metadata(target_file)
    pdb = str(pe.get("pdbpath") or "")
    lowered_pdb = pdb.lower()
    strong = sorted({t for t in CAPE_PDB_STRONG_TOKENS if t in lowered_pdb})
    weak = sorted({t for t in CAPE_PDB_WEAK_TOKENS if t in lowered_pdb})

    imported = _cape_imported_names(pe)
    lowered_imports = {name.lower() for name in imported}
    matched_imports = sorted(
        {n for n in CAPE_INJECTION_IMPORTS if n in lowered_imports}
    )
    strong_injection = sorted(
        {n for n in CAPE_STRONG_INJECTION_IMPORTS if n in lowered_imports}
    )

    points = 0
    reasons: list[str] = []
    if strong or weak:
        project_hint = bool(strong or weak)
    else:
        project_hint = False
    if strong:
        points += CAPE_PDB_STRONG_POINTS
        reasons.append("pdb_path_names_exploit_or_toolkit")
    elif weak:
        points += CAPE_PDB_WEAK_POINTS
        reasons.append("pdb_path_names_malware_project")

    injection_signal = (
        bool(strong_injection)
        or len(matched_imports) >= CAPE_INJECTION_IMPORTS_THRESHOLD
    )
    if injection_signal and (concealed or project_hint):
        points += CAPE_INJECTION_IMPORT_POINTS
        reasons.append("process_injection_imports")

    return {
        "pdb_path": pdb or None,
        "pdb_strong_tokens": strong,
        "pdb_weak_tokens": weak,
        "injection_imports": matched_imports[:12],
        "strong_injection_imports": strong_injection[:12],
        "evidence_points": points,
        "reasons": reasons,
    }

def _cape_target_file(data: dict) -> dict:
    target = data.get("target") or {}
    if not isinstance(target, dict):
        return {}
    return target.get("file") if isinstance(target.get("file"), dict) else target

def cape_static_indicators(data: dict) -> dict:
    """Static evidence that survives a sandbox that never launched the sample.

    When Windows blocks a sample before instrumentation (Defender's
    ERROR_VIRUS_INFECTED) or the sample needs elevation CAPE cannot grant
    (WinError 740), the run records no processes and malscore collapses toward 0.
    The file, however, still carries its own static proof: YARA hits on the target,
    PE anomalies, timestomping, packers. Those are scored here so a blocked malware
    sample cannot be reported as low danger.

    The floor is only meaningful for a run that never instrumented anything; a run
    that did execute produces observed behaviour and must keep its own malscore.
    """
    target_file = _cape_target_file(data)
    log = ((data.get("debug") or {}).get("log") or "")
    lowered_log = log.lower()
    sig_names = {
        str(item.get("name"))
        for item in (data.get("signatures") or [])
        if isinstance(item, dict)
    }
    yara_rules = [
        str(entry.get("name"))
        for entry in (target_file.get("yara") or []) + (target_file.get("cape_yara") or [])
        if isinstance(entry, dict) and entry.get("name")
    ]

    launch_blocked = any(marker in lowered_log for marker in CAPE_BLOCKED_LAUNCH_MARKERS)
    privileged_launch_failed = any(marker in lowered_log for marker in CAPE_PRIVILEGE_LAUNCH_MARKERS)
    if privileged_launch_failed:
        launch_blocked = True

    processes = len((data.get("behavior") or {}).get("processes") or [])
    reasons: list[str] = []
    if any(marker in lowered_log for marker in CAPE_BLOCKED_LAUNCH_MARKERS):
        reasons.append("sample_blocked_by_guest_av")
    if privileged_launch_failed:
        reasons.append("launch_requires_elevation")

    hits = sorted(name for name in CAPE_STATIC_MALWARE_SIGNATURES if name in sig_names)
    evidence_points = 0
    for name in hits:
        if name == "binary_yara" and not yara_rules:
            continue
        evidence_points += CAPE_STATIC_MALWARE_SIGNATURES[name]
    if yara_rules and not hits:
        evidence_points += CAPE_STATIC_MALWARE_SIGNATURES["binary_yara"]

    named_yara = sorted(
        rule for rule in yara_rules
        if any(token in rule.lower() for token in CAPE_YARA_FAMILY_TOKENS)
    )
    if named_yara:
        evidence_points += CAPE_YARA_FAMILY_POINTS

    pe_indicators = cape_pe_indicators(
        target_file,
        concealed=bool(set(hits) & CAPE_CONCEALMENT_SIGNATURES),
    )
    evidence_points += pe_indicators["evidence_points"]

    executable = str(target_file.get("type") or "").lower().startswith(("pe32", "ms-dos"))
    never_instrumented = processes == 0
    if not executable or not never_instrumented:
        evidence_points = 0

    static_minimum = (
        min(100, int(evidence_points * CAPE_STATIC_SCORE_PER_POINT)) if evidence_points else 0
    )
    if static_minimum:
        static_minimum = max(CAPE_STATIC_FLOOR_MINIMUM, static_minimum)
    return {
        "launch_blocked": launch_blocked,
        "sample_blocked_by_guest_av": bool(reasons and "sample_blocked_by_guest_av" in reasons),
        "launch_requires_elevation": privileged_launch_failed,
        "never_instrumented": never_instrumented,
        "reasons": reasons + pe_indicators["reasons"],
        "yara_rules": yara_rules[:5],
        "yara_family_rules": named_yara[:5],
        "detections": hits,
        "pe": pe_indicators,
        "evidence_points": evidence_points,
        "danger_score_floor": static_minimum,
    }

def calculate_cape_danger_score(report: dict | str | Path) -> float | None:
    if isinstance(report, dict):
        data = report
    else:
        try:
            with Path(report).open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            return None
    if not cape_run_quality(data).get("usable", True):
        return None
    malscore = data.get("malscore", data.get("score"))
    try:
        native_score = None if malscore is None else _clamp_score(float(malscore) * (100.0 / CAPE_NATIVE_MAX_SCORE))
    except (TypeError, ValueError):
        native_score = None
    floor = cape_static_indicators(data).get("danger_score_floor") or 0
    if floor:
        # A run that never instrumented the sample can only under-report; the static
        # floor prevents a blocked malware file from being scored as low danger.
        return round(max(native_score or 0.0, float(floor)), 2)
    return native_score

def cape_run_quality(report: dict | str | Path) -> dict:
    """Classify how much of a CAPE run actually happened.

    A CAPE report can exist while the sample never executed (`behavior.processes`
    empty on a 7-second run) or while the analysis was cut off by the sandbox time
    cap (`info.timeout`). Both look identical to `malscore` alone, and treating them
    as a clean dynamic observation understates danger. The returned `usable` flag is
    the caller-facing signal: False means the run must not be scored.
    """
    if isinstance(report, dict):
        data = report
    else:
        try:
            with Path(report).open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            return {"usable": False, "status": "unreadable", "reasons": ["report_unreadable"]}
    if not isinstance(data, dict):
        return {"usable": False, "status": "unreadable", "reasons": ["report_unreadable"]}

    info = data.get("info") or {}
    behavior = data.get("behavior") or {}
    network = data.get("network") or {}
    malstatus = str(data.get("malstatus") or "").strip()
    processes = behavior.get("processes") or []
    signature_count = len(data.get("signatures") or [])
    observed_counts = {
        "processes": len(processes),
        "signatures": signature_count,
        "dropped": len(data.get("dropped") or []),
        "payloads": len((data.get("CAPE") or {}).get("payloads") or []),
        "network": sum(len(network.get(key) or []) for key in ("http", "dns", "hosts", "tcp", "udp")),
        "ttps": len(data.get("ttps") or []),
    }
    observed_except_signatures = any(
        count for key, count in observed_counts.items() if key != "signatures"
    )

    reasons: list[str] = []
    if malstatus.lower() in CAPE_FAILED_STATES:
        reasons.append("analysis_failed")
    if info.get("timeout"):
        reasons.append("analysis_timeout")
    if observed_counts["processes"] == 0 and observed_except_signatures:
        # Static signatures fire on load; no process means the sample was never run.
        reasons.append("no_execution")

    if "analysis_failed" in reasons or not observed_except_signatures:
        status = "unusable"
    elif reasons:
        status = "partial"
    else:
        status = "complete"

    native_score = data.get("malscore", data.get("score"))
    try:
        native_malscore = None if native_score is None else float(native_score)
    except (TypeError, ValueError):
        native_malscore = None

    return {
        "usable": status != "unusable",
        "status": status,
        "reasons": reasons,
        "malscore": native_malscore,
        "malscore_scale_max": CAPE_NATIVE_MAX_SCORE,
        "malstatus": malstatus or None,
        "timed_out": bool(info.get("timeout")),
        "duration_seconds": info.get("duration"),
        "observed": observed_counts,
    }

def calculate_cape_danger_score(report: dict | str | Path) -> float | None:
    if isinstance(report, dict):
        data = report
    else:
        try:
            with Path(report).open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            return None
    floor = cape_static_indicators(data).get("danger_score_floor") or 0
    if not cape_run_quality(data).get("usable", True):
        # The run carries no usable dynamic observation, but static detections still
        # stand on their own; report the floor rather than nothing.
        return round(float(floor), 2) if floor else None
    malscore = data.get("malscore", data.get("score"))
    try:
        native_score = None if malscore is None else _clamp_score(float(malscore) * (100.0 / CAPE_NATIVE_MAX_SCORE))
    except (TypeError, ValueError):
        native_score = None
    if floor:
        # A run that never instrumented the sample can only under-report; the static
        # floor prevents a blocked malware file from being scored as low danger.
        return round(max(native_score or 0.0, float(floor)), 2)
    return native_score

def _write_report(reports_dir: Path, name: str, report: dict) -> str:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / name
    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False)
    return str(path)

def handle_mobsf(
    file_path: str,
    md5: str,
    *,
    submitted: bool = False,
    client: MobSFCall | None = None,
    report_path: str | Path | None = None,
) -> dict:
    client = client or MobSFCall()
    report_path = Path(report_path or Path("reports") / f"mobsf-{md5}.json")
    report = client.generate_json_report(md5)
    if report.get("status") is True:
        return {
            "status": True,
            "report_path": _write_report(report_path.parent, report_path.name, report.get("data") or {}),
        }
    if report.get("status") == "failed":
        return {
            "status": "failed",
            "report_path": str(report_path),
            "error": str(report.get("error", "MobSF report failed")),
        }
    if submitted:
        return {
            "status": "pending",
            "report_path": str(report_path),
            "submitted": True,
            "retry_in": 30,
        }

    ext = Path(file_path).suffix.lower()
    if ext not in MOBSF_SUPPORTED_EXTS:
        return {
            "status": "skipped",
            "report_path": str(report_path),
            "reason": "unsupported",
            "error": f"Unsupported file type for MobSF: ({ext or 'unknown'})",
        }

    upload = client.upload_file(file_path)
    if not upload.get("success"):
        if upload.get("timed_out"):
            return {
                "status": "pending",
                "report_path": str(report_path),
                "submitted": True,
                "retry_in": 30,
                "error": "MobSF upload timed out; polling for server-side report",
            }
        error = str(upload.get("error", "MobSF upload failed"))
        if "not supported" in error.lower() or "not support" in error.lower():
            return {
                "status": "skipped",
                "report_path": str(report_path),
                "error": error,
            }
        return {
            "status": "failed",
            "report_path": str(report_path),
            "error": error,
        }

    data = upload.get("data") or {}
    if isinstance(data, dict) and ("appsec" in data or "package_name" in data or "security_score" in data):
        return {
            "status": True,
            "report_path": _write_report(report_path.parent, report_path.name, data),
        }
    file_hash = data.get("hash") or md5
    scan = client.scan_uploaded_file(file_hash, timeout=10)
    if not scan.get("success"):
        return {
            "status": "failed",
            "report_path": str(report_path),
            "error": str(scan.get("error", "MobSF scan failed")),
        }
    return {
        "status": "pending",
        "report_path": str(report_path),
        "submitted": True,
        "retry_in": 30,
    }

def calculate_rampart_ai_score(report: dict) -> float | None:
    probability = report.get("malware_probability")
    if probability is None:
        return None
    try:
        return _clamp_score(float(probability) * 100)
    except (TypeError, ValueError):
        return None

def handle_rampart_ai(
    mobsf_report_path: str,
    md5: str,
    *,
    client: RampartAICall | None = None,
    report_path: str | Path | None = None,
) -> dict:
    client = client or RampartAICall()
    report_path = Path(report_path or Path("reports") / f"rampartai-{md5}.json")
    result = client.predict(mobsf_report_path)
    if not result.get("success"):
        return {
            "status": "skipped",
            "report_path": str(report_path),
            "error": str(result.get("error", "RampartAI prediction unavailable")),
        }
    data = result.get("data") or {}
    return {
        "status": True,
        "report_path": _write_report(report_path.parent, report_path.name, data),
    }

def handle_cape(
    file_path: str,
    md5: str,
    *,
    task_id=None,
    client: CAPEAnalyzer | None = None,
    reports_dir: Path = Path("reports"),
    report_path: str | Path | None = None,
) -> dict:
    client = client or CAPEAnalyzer()
    report_path = Path(report_path or reports_dir / f"cape-{md5}.json")
    package = CAPE_PACKAGE_MAP.get(Path(file_path).suffix.lower())
    if task_id is None:
        if not Path(file_path).is_file():
            return {
                "status": "failed",
                "report_path": str(report_path),
                "error": f"Upload file no longer exists on disk: {file_path}",
            }
        existing = client.cheack_analyer(file_path)
        if isinstance(existing, dict) and existing.get("error"):
            return {
                "status": "pending",
                "report_path": str(report_path),
                "error": str(existing["error"]),
                "retry_in": 30,
            }
        if existing:
            task_id = existing[0].get("id")
            retry_in = 30
        else:
            created = client.create_file_task(file_path, machine="win10", package=package)
            if created.get("status") == "error" or not created.get("task_id"):
                error = str(created.get("error", "CAPE submission failed"))
                if "machine" in error.lower():
                    error = f"{error} — ตรวจสอบชื่อ machine (win10) กับ CAPE_BASE_URL ใน .env"
                if "not supported" in error.lower() or "not support" in error.lower():
                    return {
                        "status": "skipped",
                        "report_path": str(report_path),
                        "error": error,
                    }
                return {
                    "status": "failed",
                    "report_path": str(report_path),
                    "error": error,
                }
            task_id = created["task_id"]
            retry_in = 60
        return {
            "status": "pending",
            "report_path": str(report_path),
            "task_id": task_id,
            "retry_in": retry_in,
        }

    status = client.get_task_status(task_id)
    if status.get("error"):
        return {
            "status": "pending",
            "report_path": str(report_path),
            "task_id": task_id,
            "error": str(status["error"]),
            "retry_in": 30,
        }
    state = status.get("data")
    if isinstance(state, dict):
        state = state.get("status")
    if state in {"failed_analysis", "error", "failed", "failed_reporting", "failed_processing"}:
        error = f"CAPE analysis failed: {state}"
        return {
            "status": "failed",
            "report_path": str(report_path),
            "task_id": task_id,
            "error": error,
        }
    if state != "reported":
        return {
            "status": "pending",
            "report_path": str(report_path),
            "task_id": task_id,
            "retry_in": 30,
        }

    report = client.get_report(task_id, md5)
    if report.get("status") != "success":
        return {
            "status": "pending",
            "report_path": str(report_path),
            "task_id": task_id,
            "error": str(report.get("error", "CAPE report failed")),
            "retry_in": 30,
        }
    data = report.get("data") or {}
    return {
        "status": True,
        "report_path": _write_report(report_path.parent, report_path.name, data),
        "task_id": task_id,
    }
