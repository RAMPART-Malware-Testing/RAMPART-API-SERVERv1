"""Unit tests for CAPE run-quality classification.

A CAPE report file can exist while the sandbox never actually executed the sample
(`behavior.processes` empty on a 7-second run) or while the analysis was cut off by
the sandbox time cap (`info.timeout`). Before this classifier both cases reached the
aggregator as an ordinary `cape_score = malscore * 10`, so a fake 0.0 diluted real
danger in the weighted fallback and the evidence handed to Gemini described the
sandbox as having observed clean behaviour.

The classifier must stay conservative: it may downgrade a run that never happened, but
it must never demote a run that produced real behaviour - that was the regression that
scored a genuine Microsoft installer at 80/100 and a corpus malware sample at 39/100
from the same `malscore * 10` formula.

Run from the repo root:

    venv/bin/python -m pytest tests/test_cape_run_quality.py -v
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")

from bgProcessing.report_evidence import extract_cape_evidence
from bgProcessing.task_handlers import (
    calculate_cape_danger_score,
    cape_run_quality,
    cape_static_indicators,
)


def _report(**overrides) -> dict:
    report = {
        "malscore": 7.0,
        "malstatus": "Malicious",
        "info": {"timeout": False, "duration": 120},
        "debug": {"errors": [], "log": ""},
        "behavior": {"processes": [{"process_name": "sample.exe", "calls": [{}]}]},
        "signatures": [{"name": "injection", "severity": 3, "description": "injected"}],
        "dropped": [{"sha256": "a"}],
        "CAPE": {"payloads": [{"sha256": "b"}]},
        "network": {"http": [{}], "dns": [], "hosts": [], "tcp": [], "udp": []},
        "ttps": [{"signature": "injection", "ttps": ["T1055"]}],
        "target": {"category": "file", "file": {"name": "sample.exe", "type": "PE32", "size": 100}},
    }
    report.update(overrides)
    return report


BLOCKED_LOG = (
    "[lib.api.process] ERROR: Failed to execute process from path "
    '"C:\\Temp\\sample.exe" with arguments "None" (Error: Operation did not complete '
    "successfully because the file contains a virus or potentially unwanted software "
    "(ERROR_VIRUS_INFECTED))\n[root] ERROR: You probably submitted the job with wrong package\n"
)
UAC_LOG = (
    '[lib.api.process] ERROR: Failed to execute process from path "C:\\Temp\\sample.exe" '
    'with arguments "None" (Error: 740)\n'
)


def _blocked_report(**overrides) -> dict:
    """A malware sample the sandbox guest refused to launch, exactly as CAPE records it."""
    base = dict(
        malscore=3.0,
        malstatus="Clean",
        info={"timeout": False, "duration": 33},
        debug={"errors": [], "log": BLOCKED_LOG},
        behavior={"processes": []},
        signatures=[
            {"name": "binary_yara", "severity": 3},
            {"name": "static_pe_anomaly", "severity": 3},
            {"name": "pe_compile_timestomping", "severity": 3},
            {"name": "antianalysis_tls_section", "severity": 2},
            {"name": "contains_pe_overlay", "severity": 2},
            {"name": "packer_unknown_pe_section_name", "severity": 2},
        ],
        dropped=[],
        CAPE={"payloads": []},
        network={"http": [], "dns": [], "hosts": [{}], "tcp": [{}], "udp": [{}]},
        ttps=[{"signature": "binary_yara", "ttps": ["T1071"]}],
        target={
            "category": "file",
            "file": {
                "name": "blocked.exe",
                "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "size": 590374,
                "yara": [{"name": "INDICATOR_EXE_Packed_ASPack"}],
            },
        },
    )
    base.update(overrides)
    return base


def test_completed_run_with_behaviour_is_complete_and_scored():
    quality = cape_run_quality(_report())
    assert quality["status"] == "complete"
    assert quality["usable"] is True
    assert quality["reasons"] == []
    assert calculate_cape_danger_score(_report()) == 70.0


def test_timed_out_run_stays_usable_and_keeps_its_score():
    report = _report(malscore=8.0, info={"timeout": True, "duration": 242})
    quality = cape_run_quality(report)
    assert quality["status"] == "partial"
    assert "analysis_timeout" in quality["reasons"]
    # A real detection must never be demoted just because the sandbox hit its cap.
    assert quality["usable"] is True
    assert calculate_cape_danger_score(report) == 80.0


def test_run_without_execution_is_flagged_partial():
    report = _report(
        malscore=0.0,
        malstatus=None,
        info={"timeout": False, "duration": 7},
        behavior={"processes": []},
        signatures=[],
        dropped=[],
        CAPE={"payloads": []},
        network={"http": [], "dns": [], "hosts": [{}], "tcp": [], "udp": []},
        ttps=[],
    )
    quality = cape_run_quality(report)
    assert quality["status"] == "partial"
    assert "no_execution" in quality["reasons"]
    assert quality["observed"]["processes"] == 0
    assert calculate_cape_danger_score(report) == 0.0


def test_empty_report_is_unusable_and_unscored():
    report = _report(
        malscore=0.0,
        malstatus=None,
        info={"timeout": False, "duration": 7},
        behavior={"processes": []},
        signatures=[],
        dropped=[],
        CAPE={"payloads": []},
        network={},
        ttps=[],
    )
    quality = cape_run_quality(report)
    assert quality["status"] == "unusable"
    assert quality["usable"] is False
    # The raw malscore is still readable; it is the evidence layer that withholds it.
    assert calculate_cape_danger_score(report) == 0.0
    assert extract_cape_evidence(report)["danger_score"] is None


def test_failed_analysis_is_unusable_even_with_signatures():
    report = _report(malstatus="Failed", malscore=0.0, behavior={"processes": []})
    quality = cape_run_quality(report)
    assert quality["status"] == "unusable"
    assert "analysis_failed" in quality["reasons"]
    assert extract_cape_evidence(report)["danger_score"] is None


def test_missing_malscore_is_unscored_but_not_reclassified():
    report = _report()
    del report["malscore"]
    assert cape_run_quality(report)["status"] == "complete"
    assert calculate_cape_danger_score(report) is None


def test_unreadable_path_is_unusable_without_raising(tmp_path):
    missing = tmp_path / "absent.json"
    assert cape_run_quality(missing)["usable"] is False
    assert calculate_cape_danger_score(missing) is None
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cape_run_quality(broken)["usable"] is False
    assert calculate_cape_danger_score(broken) is None


def test_reports_without_newer_keys_still_classify():
    """Reports already on disk may predate any key this classifier reads."""
    legacy = {"malscore": 3.9, "signatures": [{"name": "stealth", "severity": 1}]}
    quality = cape_run_quality(legacy)
    assert quality["status"] == "unusable"
    assert quality["malscore_scale_max"] == 10.0
    assert calculate_cape_danger_score(legacy) == 39.0
    assert extract_cape_evidence(legacy)["danger_score"] is None


def test_evidence_carries_run_quality_and_withholds_unusable_score():
    quality_report = _report(malstatus="Failed", malscore=0.0, behavior={"processes": []})
    evidence = extract_cape_evidence(quality_report)
    assert evidence["run_quality"]["usable"] is False
    assert evidence["danger_score"] is None
    assert evidence["malscore"] == 0.0

    timed_out = extract_cape_evidence(_report(malscore=8.0, info={"timeout": True, "duration": 242}))
    assert timed_out["run_quality"]["status"] == "partial"
    assert timed_out["danger_score"] == 80.0
    assert json.dumps(timed_out)  # evidence stays JSON-serialisable for the Gemini request


# --- static indicators: a sandbox that never launched the sample -------------


def test_blocked_launch_is_detected_from_the_cape_log():
    statics = cape_static_indicators(_blocked_report())
    assert statics["launch_blocked"] is True
    assert statics["sample_blocked_by_guest_av"] is True
    assert statics["never_instrumented"] is True
    assert "sample_blocked_by_guest_av" in statics["reasons"]
    assert "INDICATOR_EXE_Packed_ASPack" in statics["yara_rules"]


def test_blocked_malware_keeps_capes_own_score_and_is_marked_incomplete():
    """A blocked run measured nothing, so CAPE's score must not be inflated from it.

    The absence of observation is carried by the run classification, not by inventing
    a number the sandbox never produced.
    """
    report = _blocked_report()
    quality = cape_run_quality(report)
    assert quality["status"] == "partial"
    assert quality["reasons"] == ["no_execution"]
    # malscore 3.0 -> 30/100: CAPE's own (weak) verdict, untouched.
    assert calculate_cape_danger_score(report) == 30.0
    # ...but the static evidence is still reported as evidence of intent.
    statics = cape_static_indicators(report)
    assert statics["launch_blocked"] is True
    assert "binary_yara" in statics["detections"]
    assert statics["evidence_points"] > 0


def test_a_run_that_actually_executed_keeps_its_own_score():
    report = _report(malscore=8.0, info={"timeout": True, "duration": 242})
    assert calculate_cape_danger_score(report) == 80.0


def test_static_indicators_only_describe_executable_targets():
    """Static hints exist for any file, but they only describe PE runs that never ran."""
    report = _blocked_report(
        target={
            "category": "file",
            "file": {
                "name": "blocked.apk",
                "type": "Android package (APK), with classes.dex",
                "size": 10,
                "yara": [{"name": "INDICATOR_EXE_Packed_ASPack"}],
            },
        },
        malscore=0.0,
    )
    assert cape_static_indicators(report)["evidence_points"] == 0
    assert calculate_cape_danger_score(report) == 0.0


def test_privileged_launch_is_flagged():
    report = _blocked_report(
        debug={"errors": [], "log": UAC_LOG},
        malscore=0.0,
        malstatus="Failed",
        signatures=[{"name": "contains_pe_overlay", "severity": 2}],
        target={"category": "file", "file": {"name": "uac.exe", "type": "PE32+ executable (GUI) x86-64, for MS Windows"}},
    )
    statics = cape_static_indicators(report)
    assert statics["launch_requires_elevation"] is True
    assert statics["launch_blocked"] is True
    # Unusable means no measurement: the score is withheld rather than fabricated, and
    # the elevation requirement is what the analyst is told about.
    assert cape_run_quality(report)["usable"] is False
    assert extract_cape_evidence(report)["danger_score"] is None


def test_blocked_run_is_reported_as_incomplete_not_as_a_low_score():
    """The old floor existed so a blocked sample would not read as safe.

    The signal is now the incomplete-run classification (plus the static evidence list),
    which says "not analysed" instead of claiming a danger level nobody measured.
    """
    report = _blocked_report(
        malscore=0.0,
        signatures=[{"name": "contains_pe_overlay", "severity": 2}],
        target={"category": "file", "file": {"name": "tiny.exe", "type": "PE32 executable"}},
    )
    assert cape_run_quality(report)["status"] == "partial"
    assert cape_static_indicators(report)["evidence_points"] > 0
    assert calculate_cape_danger_score(report) == 0.0


def test_unusable_without_static_evidence_still_yields_no_score():
    report = _report(
        malscore=0.0, malstatus=None,
        info={"timeout": False, "duration": 7},
        behavior={"processes": []}, signatures=[], dropped=[],
        CAPE={"payloads": []}, network={}, ttps=[],
        target={"category": "file", "file": {"name": "empty.exe", "type": "PE32 executable"}},
    )
    assert extract_cape_evidence(report)["danger_score"] is None


def test_binary_yara_without_a_named_rule_is_ignored():
    """A severity-3 binary_yara with no actual YARA rule is a placeholder, not proof."""
    report = _blocked_report(
        signatures=[{"name": "binary_yara", "severity": 3}],
        target={"category": "file", "file": {"name": "bare.exe", "type": "PE32 executable", "yara": []}},
    )
    assert cape_static_indicators(report)["evidence_points"] == 0


def test_evidence_exposes_static_indicators_for_gemini():
    evidence = extract_cape_evidence(_blocked_report())
    assert evidence["danger_score"] == 30.0
    assert evidence["static_indicators"]["launch_blocked"] is True
    assert evidence["run_quality"]["reasons"] == ["no_execution"]


# --- run summary exposed to the API/UI ---------------------------------------


def test_cape_run_summary_reports_a_blocked_launch(tmp_path, monkeypatch):
    """The list/detail views need to know a CAPE score came from static evidence only."""
    from services.analy import analy_service

    report = _blocked_report()
    (tmp_path / "cape-deadbeefdeadbeefdeadbeefdeadbeef.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    monkeypatch.setattr(analy_service, "REPORTS_DIR", tmp_path)

    summary = analy_service.cape_run_summary("deadbeefdeadbeefdeadbeefdeadbeef")
    assert summary is not None
    assert summary["status"] == "partial"
    assert summary["sample_blocked_by_guest_av"] is True
    assert summary["coverage"] == "incomplete"
    assert "binary_yara" in summary["static_detections"]
    assert summary["static_yara_rules"] == ["INDICATOR_EXE_Packed_ASPack"]


def test_cape_run_summary_is_none_without_a_report(tmp_path, monkeypatch):
    from services.analy import analy_service

    monkeypatch.setattr(analy_service, "REPORTS_DIR", tmp_path)
    assert analy_service.cape_run_summary("00000000000000000000000000000000") is None
    assert analy_service.cape_run_summary(None) is None


# --- PE metadata indicators ---------------------------------------------------


def _pe_report(pdb="", imports=None, signatures=None, **overrides):
    pe = {"pdbpath": pdb, "imports": {}}
    if imports:
        pe["imports"] = {"KERNEL32": {"dll": "KERNEL32.dll", "imports": [{"name": n} for n in imports]}}
    base = dict(
        malscore=0.0,
        malstatus="Clean",
        info={"timeout": False, "duration": 30},
        debug={"errors": [], "log": BLOCKED_LOG},
        behavior={"processes": []},
        signatures=signatures if signatures is not None else [{"name": "packer_entropy", "severity": 2}],
        dropped=[],
        CAPE={"payloads": []},
        network={},
        ttps=[],
        target={"category": "file", "file": {"name": "x.exe", "type": "PE32+ executable (GUI) x86-64, for MS Windows", "pe": pe}},
    )
    base.update(overrides)
    return base


def test_pdb_path_naming_an_exploit_kit_is_reported_as_evidence():
    report = _pe_report(pdb=r"C:\Users\Eu\Desktop\Rats\Meus\KL2021\PlusPlus\xpl-uac-(x64)\byeintegrity8-uac-master\x64\Release\PcaPayload.pdb")
    statics = cape_static_indicators(report)
    assert "pdb_path_names_exploit_or_toolkit" in statics["pe"]["reasons"]
    assert statics["pe"]["pdb_strong_tokens"] == ["byeintegrity", "pcapayload"]
    # The path is evidence of intent for the analyst; it is not a CAPE measurement.
    assert statics["evidence_points"] > 0
    assert calculate_cape_danger_score(report) == 0.0


def test_pdb_path_naming_a_malware_project_is_reported_as_evidence():
    report = _pe_report(pdb=r"C:\Users\Izoly\Desktop\NebulaWorm\NebulaWorm\obj\Release\NebulaWorm.pdb")
    statics = cape_static_indicators(report)
    assert "pdb_path_names_malware_project" in statics["pe"]["reasons"]
    assert "worm" in statics["pe"]["pdb_weak_tokens"]
    assert statics["evidence_points"] > 0


def test_build_stub_pdb_alone_is_not_enough():
    """A benign launcher's generic 'mi_exe_stub.pdb' must not count as evidence."""
    report = _pe_report(
        pdb="mi_exe_stub.pdb",
        imports=["CreateProcessW", "MapViewOfFile", "UnmapViewOfFile", "TerminateProcess", "IsDebuggerPresent"],
        signatures=[],
    )
    assert cape_static_indicators(report)["evidence_points"] == 0


def test_yara_rule_naming_a_malware_family_is_a_detection():
    report = _blocked_report(
        target={
            "category": "file",
            "file": {
                "name": "worm.exe",
                "type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
                "yara": [{"name": "INDICATOR_SUSPICIOUS_GENRansomware"}],
            },
        },
    )
    statics = cape_static_indicators(report)
    assert statics["yara_family_rules"] == ["INDICATOR_SUSPICIOUS_GENRansomware"]
    assert statics["evidence_points"] >= 4


# --- CAPE analysis timeout plumbing ------------------------------------------


def test_analysis_timeout_prefers_environment(monkeypatch):
    from calling import CAPE

    monkeypatch.setattr(CAPE, "_master_config_analysis_timeout", lambda: 600)
    monkeypatch.setenv("CAPE_ANALYSIS_TIMEOUT", "900")
    assert CAPE.CAPEAnalyzer._analysis_timeout() == 900


def test_analysis_timeout_falls_back_to_master_config(monkeypatch):
    from calling import CAPE

    monkeypatch.setattr(CAPE, "_master_config_analysis_timeout", lambda: 750)
    monkeypatch.delenv("CAPE_ANALYSIS_TIMEOUT", raising=False)
    assert CAPE.CAPEAnalyzer._analysis_timeout() == 750


def test_analysis_timeout_ignores_broken_values(monkeypatch):
    from calling import CAPE

    monkeypatch.setattr(CAPE, "_master_config_analysis_timeout", lambda: 600)
    for bad in ("", "abc", "0", "-30"):
        monkeypatch.setenv("CAPE_ANALYSIS_TIMEOUT", bad)
        # never send an unusable number to CAPE; keep the configured fallback
        assert CAPE.CAPEAnalyzer._analysis_timeout() == 600


def test_analysis_timeout_defaults_to_none_without_config(monkeypatch):
    from calling import CAPE

    monkeypatch.setattr(CAPE, "_master_config_analysis_timeout", lambda: None)
    monkeypatch.delenv("CAPE_ANALYSIS_TIMEOUT", raising=False)
    # None means "let CAPE use its own configured timeout"
    assert CAPE.CAPEAnalyzer._analysis_timeout() is None


# --- file-intrinsic string, resource and import evidence ---------------------


def _strings_report(strings, **overrides):
    return _pe_report(strings=strings, **overrides)


def test_persistence_and_elevation_imports_are_scored():
    report = _pe_report(
        imports=["RegCreateKeyExW", "RegSetValueExW", "AdjustTokenPrivileges",
                 "OpenProcessToken", "LookupPrivilegeValueW"],
    )
    statics = cape_static_indicators(report)
    assert "persistence_imports" in statics["pe"]["reasons"]
    assert "privilege_escalation_imports" in statics["pe"]["reasons"]
    assert statics["evidence_points"] >= 4
    assert calculate_cape_danger_score(report) == 0.0


def test_pdb_path_naming_a_build_machine_is_a_hint_not_a_verdict():
    report = _pe_report(pdb=r"C:\Users\dev\Desktop\project\Release\app.pdb")
    statics = cape_static_indicators(report)
    assert "pdb_path_names_build_machine" in statics["pe"]["reasons"]
    # A build path alone is weak evidence and is weighted as such.
    assert statics["pe"]["evidence_points"] == 1


def test_shadow_copy_deletion_strings_are_strong_evidence():
    report = _strings_report([
        '"cmd.exe" /c vssadmin delete shadows /all /quiet',
        'wbadmin delete systemstatebackup -keepversions:0',
        'bcdedit /set {default} recoveryenabled No',
        'powershell Set-MpPreference -DisableRealtimeMonitoring $true',
    ])
    statics = cape_static_indicators(report)
    assert "vssadmin delete shadows" in statics["strings"]["strong_evidence_strings"]
    assert "set-mppreference" in statics["strings"]["strong_evidence_strings"]
    assert statics["evidence_points"] >= 7


def test_a_single_strong_string_outweighs_a_pile_of_generic_ones():
    generic = _strings_report(["virtualalloc", "writeprocessmemory", "createremotethread"])
    strong = _strings_report(["https://pastebin.com/raw/abc"])
    assert (
        cape_static_indicators(strong)["evidence_points"]
        > cape_static_indicators(generic)["evidence_points"]
    )


def test_common_infrastructure_strings_are_ignored():
    # Verified against the demo corpus: these appear in the benign Edge installer and
    # in signed-time-stamped binaries, so they must not raise the floor.
    report = _strings_report(
        [
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes",
            "http://ocsp.digicert.com",
            "https://crl3.digicert.com/DigiCertTrustedG4.crl",
            "Microsoft.Windows.Common-Controls",
        ],
        signatures=[{"name": "noop", "severity": 0}],
    )
    statics = cape_static_indicators(report)
    assert statics["strings"]["strong_evidence_strings"] == []
    assert statics["strings"]["suspicious_strings"] == []
    assert statics["evidence_points"] == 0


def test_string_evidence_is_read_wherever_cape_stored_it():
    for container in ("target_file", "target", "top_level"):
        report = _pe_report()
        report["target"]["file"].pop("strings", None)
        if container == "target_file":
            report["target"]["file"]["strings"] = ["vssadmin delete shadows"]
        elif container == "target":
            report["target"]["strings"] = [{"string": "vssadmin delete shadows"}]
        else:
            report["strings"] = [{"value": "vssadmin delete shadows"}]
        statics = cape_static_indicators(report)
        assert statics["strings"]["strong_evidence_strings"] == ["vssadmin delete shadows"], container


def test_versioninfo_spoofing_a_brand_is_flagged():
    report = _pe_report()
    report["target"]["file"]["pe"]["versioninfo"] = [
        {"name": "InternalName", "value": "jusched"},
        {"name": "CompanyName", "value": "Oracle Corporation"},
        {"name": "FileDescription", "value": "Java Update Installer"},
    ]
    statics = cape_static_indicators(report)
    assert "impersonates_known_brand" in statics["resources"]["reasons"]
    assert "social_engineering_resource_names" in statics["resources"]["reasons"]
    assert statics["evidence_points"] >= 3


def test_resource_names_alone_are_weak():
    report = _pe_report(signatures=[{"name": "noop", "severity": 0}])
    report["target"]["file"]["pe"]["resources"] = [
        {"name": "RT_MANIFEST", "language": "LANG_ENGLISH"},
    ]
    statics = cape_static_indicators(report)
    assert statics["evidence_points"] == 0


def test_string_and_resource_evidence_cannot_lift_an_executed_run():
    report = _pe_report(strings=["vssadmin delete shadows", "set-mppreference"])
    report["behavior"] = {"processes": [{"process_name": "x.exe", "pid": 100}]}
    statics = cape_static_indicators(report)
    assert statics["never_instrumented"] is False
    assert statics["evidence_points"] == 0


def test_static_indicators_expose_the_new_evidence_shapes():
    report = _strings_report(["schtasks /create /tn x /tr y", "reg add \\\\HKLM\\\\Run"])
    report["target"]["file"]["pe"]["resources"] = [{"name": "RT_VERSION"}]
    statics = cape_static_indicators(report)
    for key in ("strings", "resources"):
        assert key in statics
    assert set(statics["strings"]) == {
        "string_count", "suspicious_strings", "strong_evidence_strings", "evidence_points",
    }
    assert set(statics["resources"]) == {
        "brands", "attention_words", "evidence_points", "reasons",
    }
