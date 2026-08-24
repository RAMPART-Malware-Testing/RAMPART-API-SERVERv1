import argparse
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bgProcessing.report_evidence import build_gemini_evidence
from calling.GeminiAPI import GeminiAPI


def main() -> None:
    parser = argparse.ArgumentParser(description="Test compact report evidence with Gemini.")
    parser.add_argument("--virustotal", required=True)
    parser.add_argument("--mobsf")
    parser.add_argument("--cape")
    parser.add_argument("--evidence-only", action="store_true")
    args = parser.parse_args()

    evidence = build_gemini_evidence(args.virustotal, args.mobsf, args.cape)
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    print(f"Compact evidence characters: {len(json.dumps(evidence, ensure_ascii=False))}")
    if not args.evidence_only:
        assessment = GeminiAPI().AnalysisGemini(evidence)
        print(json.dumps(assessment, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
