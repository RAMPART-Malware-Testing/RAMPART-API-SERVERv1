# VT MobSF CAPE Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Continue clean VirusTotal analyses through MobSF and CAPE, persist normalized danger scores, and keep Celery retry payloads small by passing report paths and external task IDs instead of report JSON.

**Architecture:** One Celery task advances through explicit VirusTotal, MobSF, and CAPE phases. Each completed tool writes a normalized JSON report to disk; retries carry only paths, submission flags, task IDs, and poll counters. VirusTotal detection above zero terminates immediately as malicious, while MobSF/CAPE failures produce nullable scores and allow the other tool to finish.

**Tech Stack:** Python, Celery, PostgreSQL, SQLAlchemy, VirusTotal API, MobSF API, CAPE API, pytest.

## Global Constraints

- VirusTotal runs first.
- Any VirusTotal malicious engine detection stops the pipeline and marks the file malicious.
- VirusTotal clean results continue to MobSF and CAPE.
- MobSF danger score is `100 - security_score`, clamped to `0..100`.
- CAPE danger score is `malscore * 10`, clamped to `0..100`.
- Unsupported or failed MobSF/CAPE analysis stores `NULL` for that score and does not block the other tool.
- Celery retry kwargs may contain only scalar state, report paths, and external task IDs; never report dictionaries.
- Completed tool phases must not repeat after retry.
- RAMPART AI and Gemini are excluded.
- Do not commit and do not use GitHub operations.

---

### Task 1: Path-Based MobSF And CAPE Pipeline

**Files:**
- Modify: `bgProcessing/task_handlers.py`
- Modify: `bgProcessing/tasks.py`
- Modify: `calling/MobSF.py`
- Modify: `calling/CAPE.py`
- Modify: `controller/analysis_controller.py`
- Test: `tests/test_analysis_pipeline.py`
- Test: `tests/test_virustotal_task.py`

**Interfaces:**
- Produces: `handle_mobsf(...)`, `handle_cape(...)`, `calculate_mobsf_danger_score(...)`, `calculate_cape_danger_score(...)`.
- Retry kwargs: `file_path`, `md5`, `sha256`, `total_size`, `vt_report_path`, `mobsf_report_path`, `mobsf_submitted`, `mobsf_poll_count`, `cape_report_path`, `cape_task_id`, `cape_poll_count`.
- Persists: `Reports.virustotal_score`, `Reports.mobsf_score`, `Reports.cape_score` and `Analysis.tools/status/rid`.

- [ ] Write failing handler tests for MobSF report hit, submit/poll, unsupported/error, score conversion, CAPE existing/new task, poll/report, error, and score conversion.
- [ ] Run `python -m pytest tests/test_analysis_pipeline.py -q` and verify failures are due to missing handlers.
- [ ] Implement normalized handler states `complete`, `pending`, `skipped`, and `error`, with report files written before returning `complete`.
- [ ] Write failing task tests proving VT malicious short-circuits, VT clean continues, completed report paths skip repeated tools, retry kwargs contain no dictionaries, one sandbox failure does not block the other, and scores persist correctly.
- [ ] Implement the path-based Celery state machine and bounded per-tool poll counts.
- [ ] Update task-status response to expose all three scores and tools.
- [ ] Run focused tests, full tests, compileall, pip check, and diff check.
