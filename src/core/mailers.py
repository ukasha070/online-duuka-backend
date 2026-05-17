from email.message import EmailMessage
from email.utils import formataddr

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import settings

TEMPLATES_DIR = settings.BASE_DIR / "templates"


jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


class EmailService:
    @staticmethod
    def render_template(template_name: str, context: dict) -> str:
        template = jinja_env.get_template(template_name)
        return template.render(**context)

    @staticmethod
    async def send_email(
        to_email: str,
        subject: str,
        plain_body: str,
        html_body: str,
    ) -> None:
        message = EmailMessage()

        message["From"] = formataddr(
            (settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL)
        )
        message["To"] = to_email
        message["Subject"] = subject

        message.set_content(plain_body)
        message.add_alternative(html_body, subtype="html")

        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=settings.SMTP_PASSWORD,
            use_tls=settings.SMTP_USE_TLS,
            start_tls=settings.SMTP_STARTTLS if not settings.SMTP_USE_TLS else False,
            timeout=30,
        )


email_service = EmailService()
