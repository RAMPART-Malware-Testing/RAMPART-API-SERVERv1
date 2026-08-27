import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(to: str, subject: str, text_body: str, html_body: str | None = None) -> bool:
    host = os.getenv("SMTP_HOST")
    gmail_user = os.getenv("GMAIL_USERNAME")
    gmail_pass = os.getenv("GMAIL_PASSWORD")

    if not host and not (gmail_user and gmail_pass):
        print(f"[Mailer] {subject} -> {to}:\n{text_body}")
        return True

    if host:
        smtp_host = host
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASSWORD")
        sender = os.getenv("SMTP_FROM", smtp_user)
    else:
        smtp_host = "smtp.gmail.com"
        smtp_port = 587
        smtp_user = gmail_user
        smtp_pass = gmail_pass
        sender = os.getenv("SMTP_FROM", gmail_user)

    try:
        if html_body:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
        else:
            msg = MIMEText(text_body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.sendmail(sender, [to], msg.as_string())
        return True
    except Exception as exc:
        print(f"[Mailer] send failed to {to}: {exc}")
        return False
