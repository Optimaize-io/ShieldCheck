import logging
import mimetypes
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _smtp_configured() -> bool:
    return bool(os.environ.get("SELFCHECK_SMTP_HOST"))


def send_self_check_report(
    *,
    recipient_email: str,
    recipient_name: str,
    domain: str,
    pdf_path: str,
    report_url: str,
) -> str:
    """
    Send the self-check report if SMTP is configured.

    Returns one of:
    - sent
    - pending_manual
    - failed:<reason>
    """

    if not _smtp_configured():
        return "pending_manual"

    smtp_host = os.environ.get("SELFCHECK_SMTP_HOST", "")
    smtp_port = int(os.environ.get("SELFCHECK_SMTP_PORT", "587"))
    smtp_user = os.environ.get("SELFCHECK_SMTP_USER", "")
    smtp_pass = os.environ.get("SELFCHECK_SMTP_PASS", "")
    smtp_tls = os.environ.get("SELFCHECK_SMTP_TLS", "true").lower() != "false"
    sender_email = os.environ.get("SELFCHECK_FROM_EMAIL", smtp_user or "no-reply@localhost")
    sender_name = os.environ.get("SELFCHECK_FROM_NAME", "ShieldCheck")

    message = EmailMessage()
    message["Subject"] = f"Your ShieldCheck NIS2 scan for {domain}"
    message["From"] = f"{sender_name} <{sender_email}>"
    message["To"] = recipient_email

    greeting_name = recipient_name.strip() or "there"
    message.set_content(
        "\n".join(
            [
                f"Hi {greeting_name},",
                "",
                f"Your NIS2 self-check for {domain} is ready.",
                f"Web report: {report_url}",
                "",
                "The PDF report is attached.",
                "",
                "ShieldCheck",
            ]
        )
    )

    path = Path(pdf_path)
    mime_type, _ = mimetypes.guess_type(str(path))
    main_type, sub_type = (mime_type or "application/pdf").split("/", 1)
    with open(path, "rb") as handle:
        message.add_attachment(
            handle.read(),
            maintype=main_type,
            subtype=sub_type,
            filename=path.name,
        )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            if smtp_tls:
                server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.send_message(message)
        return "sent"
    except Exception as exc:  # pragma: no cover - network/environment dependent
        logger.warning("Failed to send self-check report email: %s", exc)
        return f"failed:{type(exc).__name__}"
