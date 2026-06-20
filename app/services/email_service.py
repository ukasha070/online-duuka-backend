from __future__ import annotations

from email.message import EmailMessage
from email.utils import formataddr
from typing import Any

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

from app.config import settings

TEMPLATES_DIR = settings.BASE_DIR / "templates"

jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


class EmailService:
    def render_template(self, template_name: str, context: dict[str, Any]) -> str:
        """Render a Jinja template, with a safe fallback if templates are missing."""
        try:
            template = jinja_env.get_template(template_name)
            return template.render(**context)
        except TemplateNotFound:
            return self._fallback_template(template_name, context)

    async def send_email(
        self,
        *,
        to_email: str,
        subject: str,
        plain_body: str,
        html_body: str | None = None,
    ) -> None:
        message = EmailMessage()
        message["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))
        message["To"] = to_email
        message["Subject"] = subject

        message.set_content(plain_body)
        if html_body:
            message.add_alternative(html_body, subtype="html")

        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=settings.SMTP_PASSWORD,
            use_tls=settings.SMTP_USE_TLS,
            start_tls=settings.SMTP_STARTTLS if not settings.SMTP_USE_TLS else False,
            timeout=settings.SMTP_TIMEOUT_SECONDS,
        )

    @staticmethod
    def _fallback_template(template_name: str, context: dict[str, Any]) -> str:
        app_name = context.get("app_name", settings.APP_NAME)
        full_name = context.get("full_name", "there")

        if template_name.endswith(".html"):
            lines = [
                f"<p>Hello {full_name},</p>",
                f"<p>This is a notification from {app_name}.</p>",
            ]
            for key, value in context.items():
                if key.endswith("_link") and value:
                    lines.append(f'<p><a href="{value}">{value}</a></p>')
                elif key in {"otp_code", "heading", "description"} and value:
                    lines.append(f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>")
            return "\n".join(lines)

        lines = [
            f"Hello {full_name},",
            "",
            f"This is a notification from {app_name}.",
        ]
        for key, value in context.items():
            if key.endswith("_link") and value:
                lines.extend(["", f"{key.replace('_', ' ').title()}: {value}"])
            elif key in {"otp_code", "heading", "description"} and value:
                lines.extend(["", f"{key.replace('_', ' ').title()}: {value}"])
        return "\n".join(lines)


email_service = EmailService()
