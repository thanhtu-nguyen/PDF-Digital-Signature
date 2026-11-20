from email.message import EmailMessage
import smtplib
import ssl

from .config import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_STARTTLS, SMTP_USERNAME


def send_email(to_address: str, subject: str, body: str):
    if not SMTP_HOST or not SMTP_FROM:
        raise RuntimeError("SMTP chưa được cấu hình.")
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
