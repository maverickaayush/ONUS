"""Email delivery abstraction (auth OTP). Two backends, chosen by
config.EMAIL_BACKEND:

  'console' — DEV ONLY. Logs the OTP instead of sending. Refused when
              REQUIRE_AUTH is on unless EMAIL_DEV_CONSOLE_OK is *also* explicitly
              set, so a hosted deployment can never silently print OTPs to logs.
  'smtp'    — real delivery via stdlib smtplib (STARTTLS), configured entirely
              from env (no vendor SDK, no paid dependency).

Auth logic depends only on send_otp_email() — swapping providers is a config
change, never a code change.
"""
import logging
import smtplib
from email.message import EmailMessage

from config import settings

logger = logging.getLogger(__name__)


class EmailConfigError(RuntimeError):
    """Raised when the selected backend is unusable (e.g. console in prod, or
    SMTP without a host). Callers map this to a generic 'email unavailable'."""


def _console_allowed() -> bool:
    # Allowed in local/self-hosted (REQUIRE_AUTH off), or when an operator has
    # explicitly opted in even under REQUIRE_AUTH.
    return (not settings.REQUIRE_AUTH) or settings.EMAIL_DEV_CONSOLE_OK


def _send_console(to: str, code: str) -> None:
    if not _console_allowed():
        raise EmailConfigError(
            "Console email backend is disabled under REQUIRE_AUTH. Configure "
            "EMAIL_BACKEND=smtp (or set EMAIL_DEV_CONSOLE_OK explicitly)."
        )
    # Dev convenience only — this line is exactly what the production gate above
    # prevents from ever running on a hosted deployment.
    logger.warning("[DEV EMAIL] OTP for %s is %s (expires in %ss)",
                   to, code, settings.OTP_TTL_SECONDS)


def _send_smtp(to: str, code: str) -> None:
    if not settings.SMTP_HOST:
        raise EmailConfigError("SMTP_HOST is not configured.")
    msg = EmailMessage()
    msg["Subject"] = "Your ONUS verification code"
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = to
    msg.set_content(
        f"Your ONUS verification code is {code}.\n\n"
        f"It expires in {settings.OTP_TTL_SECONDS // 60} minutes. "
        f"If you did not request this, you can ignore this email."
    )
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as s:
            if settings.SMTP_STARTTLS:
                s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        # Never leak SMTP internals to the caller/browser.
        logger.error("SMTP send to %s failed: %s", to, e.__class__.__name__)
        raise EmailConfigError("Email delivery failed.") from e


def send_otp_email(to: str, code: str) -> None:
    """Deliver an OTP via the configured backend. Raises EmailConfigError on any
    delivery/config problem; the plaintext code is never logged by the smtp path."""
    if settings.EMAIL_BACKEND == "smtp":
        _send_smtp(to, code)
    else:
        _send_console(to, code)
