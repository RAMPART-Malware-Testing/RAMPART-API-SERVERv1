"""Tests for the RampartAI classifier integration.

Covers: calling/RampartAI.py (the HTTP client), task_handlers.handle_rampart_ai
(the pipeline handler that feeds it a MobSF report), and
task_handlers.calculate_rampart_ai_score (0-1 probability -> 0-100 score).
"""

import json

import pytest

from bgProcessing import task_handlers
from calling.RampartAI import RampartAICall

class FakeRampartAIClient:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def predict(self, mobsf_report_path):
        self.calls.append(mobsf_report_path)
        return self.result

def test_rampart_ai_client_requires_configured_url(monkeypatch):
    monkeypatch.delenv("RAMPARTAI_URL", raising=False)
    client = RampartAICall()
    result = client.predict("does-not-matter.json")
    assert result["success"] is False
    assert "RAMPARTAI_URL" in result["error"]

def test_rampart_ai_client_rejects_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("RAMPARTAI_URL", "http://rampartai.test")
    client = RampartAICall()
    missing = tmp_path / "missing.json"
    result = client.predict(str(missing))
    assert result["success"] is False
    assert "not found" in result["error"].lower()

def test_rampart_ai_client_posts_report_and_returns_prediction(monkeypatch, tmp_path):
    monkeypatch.setenv("RAMPARTAI_URL", "http://rampartai.test")
    report_path = tmp_path / "mobsf-abc.json"
    report_path.write_text(json.dumps({"app_name": "sample"}), encoding="utf-8")

    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "malware_probability": 0.87,
                "benign_probability": 0.13,
                "prediction": "malware",
                "confidence": 0.87,
            }

    def fake_post(url, files=None, timeout=None):
        captured["url"] = url
        captured["files"] = files
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("calling.RampartAI.requests.post", fake_post)

    client = RampartAICall()
    result = client.predict(str(report_path))

    assert result == {
        "success": True,
        "data": {
            "malware_probability": 0.87,
            "benign_probability": 0.13,
            "prediction": "malware",
            "confidence": 0.87,
        },
    }
    assert captured["url"] == "http://rampartai.test/predict"
    assert "file" in captured["files"]

def test_rampart_ai_client_surfaces_non_200_as_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("RAMPARTAI_URL", "http://rampartai.test")
    report_path = tmp_path / "mobsf-abc.json"
    report_path.write_text("{}", encoding="utf-8")

    class FakeResponse:
        status_code = 400
        text = "Invalid JSON report."

    monkeypatch.setattr(
        "calling.RampartAI.requests.post",
        lambda *a, **k: FakeResponse(),
    )

    client = RampartAICall()
    result = client.predict(str(report_path))
    assert result["success"] is False
    assert "400" in result["error"]

@pytest.mark.parametrize(("probability", "expected"), [
    (0.0, 0.0),
    (0.5, 50.0),
    (1.0, 100.0),
    (0.000358, 0.04),
])
def test_calculate_rampart_ai_score(probability, expected):
    assert task_handlers.calculate_rampart_ai_score({"malware_probability": probability}) == expected

def test_calculate_rampart_ai_score_missing_field_is_null():
    assert task_handlers.calculate_rampart_ai_score({}) is None

def test_calculate_rampart_ai_score_invalid_type_is_null():
    assert task_handlers.calculate_rampart_ai_score({"malware_probability": "invalid"}) is None

def test_handle_rampart_ai_writes_report_on_success(tmp_path):
    mobsf_report = tmp_path / "mobsf-x.json"
    mobsf_report.write_text("{}", encoding="utf-8")
    report_path = tmp_path / "rampartai-x.json"
    client = FakeRampartAIClient({
        "success": True,
        "data": {"malware_probability": 0.9, "prediction": "malware"},
    })

    result = task_handlers.handle_rampart_ai(
        str(mobsf_report), "x" * 32, client=client, report_path=report_path
    )

    assert result["status"] is True
    assert result["report_path"] == str(report_path)
    assert json.loads(report_path.read_text()) == {"malware_probability": 0.9, "prediction": "malware"}
    assert client.calls == [str(mobsf_report)]

def test_handle_rampart_ai_skips_on_client_failure_without_blocking_pipeline(tmp_path):
    """An unavailable/misconfigured RampartAI service must degrade to
    'skipped', not 'failed' - it must never abort the whole analysis."""
    mobsf_report = tmp_path / "mobsf-y.json"
    mobsf_report.write_text("{}", encoding="utf-8")
    client = FakeRampartAIClient({"success": False, "error": "Connection refused"})

    result = task_handlers.handle_rampart_ai(
        str(mobsf_report), "y" * 32, client=client, report_path=tmp_path / "rampartai-y.json"
    )

    assert result["status"] == "skipped"
    assert "Connection refused" in result["error"]
