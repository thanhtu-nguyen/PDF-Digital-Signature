from email.message import EmailMessage
import smtplib
import ssl

import httpx

from .config import (
    RESEND_API_KEY, SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT,
    SMTP_STARTTLS, SMTP_USERNAME,
)


def send_email(to_address: str, subject: str, body: str):
    if not SMTP_FROM:
        raise RuntimeError("Chưa cấu hình địa chỉ người gửi SMTP_FROM.")

    # Prefer the HTTPS API on serverless platforms. SMTP remains available for
    # local/VPS deployments and is always awaited before the request completes.
    if RESEND_API_KEY:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": SMTP_FROM,
                "to": [to_address],
                "subject": subject,
                "text": body,
            },
            timeout=20.0,
        )
        response.raise_for_status()
        return response.json()

    if not SMTP_HOST:
        raise RuntimeError("Chưa cấu hình RESEND_API_KEY hoặc SMTP_HOST.")
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        if SMTP_STARTTLS:
            server.starttls(context=context)
            server.ehlo()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)
