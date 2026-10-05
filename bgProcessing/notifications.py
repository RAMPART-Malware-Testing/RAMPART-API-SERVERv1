import asyncio

from sqlalchemy import update

from cores.Schema.schema_class import Analysis, Reports, User
from services.fcm_service import FCMService
from utils.mailer import send_email

FRONTEND_URL = None

PUSH_ROUTE_RESULT = "/analysis-result"
PUSH_ROUTE_PROGRESS = "/analysis-progress"

# FCM answers 404 for these once a token can never deliver again (app
# uninstalled, data cleared, project unlinked). Anything else is a transient
# failure worth retrying on the next analysis, so the token has to stay.
DEAD_TOKEN_ERRORS = {"UNREGISTERED", "INVALID_ARGUMENT", "SENDER_ID_MISMATCH"}


def _get_frontend_url() -> str:
    global FRONTEND_URL
    if FRONTEND_URL is None:
        import os
        FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
    return FRONTEND_URL


def _first_dead_token_error(result: dict):
    """FCM reports per-token failures in an array next to the HTTP 200."""
    detail = (result.get("fcm_response") or {}).get("error", {})
    for item in detail.get("details") or []:
        err_type = (item.get("errorCode") or item.get("@type") or "").rsplit("/", 1)[-1]
        if err_type in DEAD_TOKEN_ERRORS:
            return err_type
    return None


async def _push_to_user(db, user, title: str, body: str, route: str, task_id: str) -> None:
    token = user.fcm_token
    if not token:
        return

    result = await FCMService.send_notification(
        token=token,
        title=title,
        body=body,
        data={"route": route, "task_id": task_id},
    )

    dead = _first_dead_token_error(result)
    if not dead:
        return

    print(f"[FCM] Clearing dead token for uid={user.uid}: {dead}")
    db.execute(update(User).where(User.uid == user.uid).values(fcm_token=None))
    db.commit()


async def _push_analysis_result(db, task_id: str, succeeded: bool) -> None:
    """Tell the user's phone that the analysis finished.

    The app already knows this payload shape: `data.route` decides which screen
    opens and `data.task_id` tells it which analysis to open there, so a tap
    lands on the result rather than on the dashboard.

    The wording is built here rather than at the call site so callers do not
    have to have the report row in scope just to name it.
    """
    row = (
        db.query(Analysis, Reports, User)
        .join(User, Analysis.uid == User.uid)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .filter(Analysis.task_id == task_id)
        .first()
    )
    if row is None:
        return
    analysis, report, user = row
    if not user or not user.fcm_token:
        return

    file_name = analysis.file_name or "ไฟล์ของคุณ"
    if succeeded:
        risk = (report.risk_level if report else None) or "ไม่ระบุความเสี่ยง"
        title = "วิเคราะห์ไฟล์เสร็จแล้ว"
        body = f"{file_name} — ความเสี่ยง: {risk}"
        route = PUSH_ROUTE_RESULT
    else:
        title = "วิเคราะห์ไฟล์ไม่สำเร็จ"
        body = f"{file_name} — กรุณาลองอัปโหลดใหม่อีกครั้ง"
        route = PUSH_ROUTE_PROGRESS

    await _push_to_user(db, user, title, body, route, task_id)


def push_analysis_result(db, task_id: str, succeeded: bool) -> None:
    """Sync entry point for the Celery worker, which has no event loop."""
    asyncio.run(_push_analysis_result(db, task_id, succeeded=succeeded))


def notify_analysis_success(db, task_id: str) -> None:
    row = (
        db.query(Analysis, Reports, User)
        .join(User, Analysis.uid == User.uid)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .filter(Analysis.task_id == task_id)
        .first()
    )
    if row is None:
        return
    analysis, report, user = row
    if not user or not user.email:
        return

    score = float(report.score) if report and report.score is not None else None
    risk_level = report.risk_level if report else None
    file_name = analysis.file_name or "ไฟล์ของคุณ"
    report_url = f"{_get_frontend_url()}/scan/analysis?taskId={task_id}"

    risk_text = risk_level or "ไม่ระบุ"
    score_text = f"{score}/100" if score is not None else "ไม่ระบุ"

    text_body = (
        f"การวิเคราะห์ไฟล์ '{file_name}' เสร็จสมบูรณ์แล้ว\n\n"
        f"ระดับความเสี่ยง: {risk_text}\n"
        f"คะแนนความปลอดภัย: {score_text}\n"
        f"สถานะมัลแวร์: {'ตรวจพบความเสี่ยง' if analysis.is_malicious else 'ไม่พบความเสี่ยง'}\n\n"
        f"ดูรายงานฉบับเต็มได้ที่: {report_url}"
    )
    html_body = f"""
    <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto">
      <h2 style="color:#0d7a53">การวิเคราะห์เสร็จสมบูรณ์</h2>
      <p>ไฟล์ <b>{file_name}</b> วิเคราะห์เสร็จแล้ว</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0">
        <tr><td style="padding:8px;border:1px solid #e5e7eb">ระดับความเสี่ยง</td><td style="padding:8px;border:1px solid #e5e7eb"><b>{risk_text}</b></td></tr>
        <tr><td style="padding:8px;border:1px solid #e5e7eb">คะแนนความปลอดภัย</td><td style="padding:8px;border:1px solid #e5e7eb"><b>{score_text}</b></td></tr>
        <tr><td style="padding:8px;border:1px solid #e5e7eb">สถานะมัลแวร์</td><td style="padding:8px;border:1px solid #e5e7eb"><b>{'ตรวจพบความเสี่ยง' if analysis.is_malicious else 'ไม่พบความเสี่ยง'}</b></td></tr>
      </table>
      <a href="{report_url}" style="display:inline-block;padding:10px 20px;background:#0d7a53;color:#fff;text-decoration:none;border-radius:8px">ดูรายงานฉบับเต็ม</a>
    </div>
    """
    send_email(user.email, f"ผลการวิเคราะห์: {file_name}", text_body, html_body)


def notify_analysis_failed(db, task_id: str, error_message: str) -> None:
    row = (
        db.query(Analysis, User)
        .join(User, Analysis.uid == User.uid)
        .filter(Analysis.task_id == task_id)
        .first()
    )
    if row is None:
        return
    analysis, user = row
    if not user or not user.email:
        return

    file_name = analysis.file_name or "ไฟล์ของคุณ"
    text_body = (
        f"การวิเคราะห์ไฟล์ '{file_name}' ไม่สำเร็จ\n\n"
        f"สาเหตุ: {error_message}\n\n"
        f"กรุณาลองอัปโหลดใหม่อีกครั้ง หรือติดต่อผู้ดูแลระบบหากปัญหายังคงอยู่"
    )
    html_body = f"""
    <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto">
      <h2 style="color:#b72e3c">การวิเคราะห์ไม่สำเร็จ</h2>
      <p>ไฟล์ <b>{file_name}</b> วิเคราะห์ไม่สำเร็จ</p>
      <p style="color:#666">สาเหตุ: {error_message}</p>
      <p>กรุณาลองอัปโหลดใหม่อีกครั้ง หรือติดต่อผู้ดูแลระบบหากปัญหายังคงอยู่</p>
    </div>
    """
    send_email(user.email, f"การวิเคราะห์ไม่สำเร็จ: {file_name}", text_body, html_body)
