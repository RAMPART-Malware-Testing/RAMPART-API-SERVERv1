from cores.Schema.schema_class import Reports
from cores.sync_pg_db import SyncSessionLocal


db = SyncSessionLocal()

malware_signatures = [
    "apk.trojan.banker",
    "Android.Malware.Trojan",
    "Trojan ( 006d9f731 )",
    "AppRisk:Generisk",
    "Trojan.Gen.NPE",
    "Android/Agent.FOQ trojan",
    "Android:Evo-gen [Trj]",
    "UDS:Trojan-Banker.AndroidOS.Agent.abd",
    "TrojanBanker:Android/Agent.79463349",
    "a.privacy.BankBotSteal",
    "Andr/Xgen4-EW",
    "Malware.ANDROID/Evo.AG1566022.Gen",
    "Android.Banker.1067.origin",
    "ti!557C02B5E9CA",
    "Detected",
    "ANDROID/Evo.AG1566022.Gen",
    "AndroidOS/ABPWS.XORH-8",
    "Android.Troj.Agent.FOQ",
    "Andr/Xgen4-EW",
    "APK:RepMalware [Trj]",
    "Malicious (score: 99)",
    "Android.Trojan.Banker.AYP",
    "Trojan/Android.SpyAgent.1323424",
    "Trojan.AndroidOS.Agent",
    "Trojan.Agent/Android!8.358 (CLOUD)",
    "Artemis!E931D549C340",
    "Android/Agent.FOQ!tr",
    "Android:Evo-gen [Trj]"
]

for i in range(100000):
    report = Reports(
        file_type="unknown",
        virustotal_score=70,
        mobsf_score=None,
        cape_score=None,
        rampart_score=0.0,
        gemini_recommendation=None,
        malware_signatures=malware_signatures,
    )
    db.add(report)
db.commit()