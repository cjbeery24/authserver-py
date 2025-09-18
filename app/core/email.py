"""
Email utilities for sending password reset and verification emails.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails with templates and configuration."""

    def __init__(self):
        self.smtp_server = settings.email_host
        self.smtp_port = settings.email_port
        self.username = settings.email_username
        self.password = settings.email_password
        self.from_email = settings.email_from
        self.use_tls = settings.email_use_tls
        self.use_ssl = settings.email_use_ssl

    async def send_email(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[str]] = None
    ) -> bool:
        """
        Send an email with HTML and optional text content.
        
        Args:
            to_emails: List of recipient email addresses
            subject: Email subject line
            html_content: HTML email content
            text_content: Plain text email content (optional)
            attachments: List of file paths to attach (optional)
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        if not settings.email_enabled:
            logger.info(f"Email sending disabled. Would send email to {to_emails} with subject: {subject}")
            return True

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = subject

            # Add text content if provided
            if text_content:
                text_part = MIMEText(text_content, 'plain', 'utf-8')
                msg.attach(text_part)

            # Add HTML content
            html_part = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(html_part)

            # Add attachments if provided
            if attachments:
                for file_path in attachments:
                    if Path(file_path).exists():
                        with open(file_path, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                        
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {Path(file_path).name}'
                        )
                        msg.attach(part)

            # Send email
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                if self.use_tls:
                    server.starttls()

            if self.username and self.password:
                server.login(self.username, self.password)

            server.sendmail(self.from_email, to_emails, msg.as_string())
            server.quit()

            logger.info(f"Email sent successfully to {to_emails}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_emails}: {str(e)}")
            return False

    async def send_password_reset_email(self, email: str, username: str, reset_token: str) -> bool:
        """
        Send password reset email with reset link.
        
        Args:
            email: User's email address
            username: User's username
            reset_token: Password reset token
            
        Returns:
            bool: True if email sent successfully
        """
        reset_url = f"{settings.frontend_url}/reset-password?token={reset_token}"
        
        subject = f"Password Reset Request - {settings.app_name}"
        
        html_content = self._get_password_reset_html_template(
            username=username,
            reset_url=reset_url,
            app_name=settings.app_name,
            expiry_hours=settings.password_reset_token_expire_hours
        )
        
        text_content = self._get_password_reset_text_template(
            username=username,
            reset_url=reset_url,
            app_name=settings.app_name,
            expiry_hours=settings.password_reset_token_expire_hours
        )

        return await self.send_email(
            to_emails=[email],
            subject=subject,
            html_content=html_content,
            text_content=text_content
        )

    async def send_password_changed_notification(self, email: str, username: str) -> bool:
        """
        Send notification email when password is successfully changed.
        
        Args:
            email: User's email address
            username: User's username
            
        Returns:
            bool: True if email sent successfully
        """
        subject = f"Password Changed - {settings.app_name}"
        
        html_content = self._get_password_changed_html_template(
            username=username,
            app_name=settings.app_name
        )
        
        text_content = self._get_password_changed_text_template(
            username=username,
            app_name=settings.app_name
        )

        return await self.send_email(
            to_emails=[email],
            subject=subject,
            html_content=html_content,
            text_content=text_content
        )

    def _get_password_reset_html_template(self, username: str, reset_url: str, app_name: str, expiry_hours: int) -> str:
        """Generate HTML template for password reset email."""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset Request</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f8f9fa; }}
                .button {{ display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 16px 0; }}
                .footer {{ padding: 20px; text-align: center; color: #666; font-size: 12px; }}
                .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 16px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{app_name}</h1>
                    <h2>Password Reset Request</h2>
                </div>
                <div class="content">
                    <p>Hello {username},</p>
                    <p>We received a request to reset your password. If you made this request, click the button below to reset your password:</p>
                    <p style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; background-color: #e9ecef; padding: 10px; border-radius: 4px;">
                        {reset_url}
                    </p>
                    <div class="warning">
                        <strong>Important:</strong> This link will expire in {expiry_hours} hour(s). If you didn't request this password reset, please ignore this email or contact support if you have concerns.
                    </div>
                    <p>For security reasons, this link can only be used once.</p>
                </div>
                <div class="footer">
                    <p>This is an automated message from {app_name}. Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _get_password_reset_text_template(self, username: str, reset_url: str, app_name: str, expiry_hours: int) -> str:
        """Generate text template for password reset email."""
        return f"""
{app_name} - Password Reset Request

Hello {username},

We received a request to reset your password. If you made this request, visit the following link to reset your password:

{reset_url}

IMPORTANT: This link will expire in {expiry_hours} hour(s). If you didn't request this password reset, please ignore this email or contact support if you have concerns.

For security reasons, this link can only be used once.

This is an automated message from {app_name}. Please do not reply to this email.
        """

    def _get_password_changed_html_template(self, username: str, app_name: str) -> str:
        """Generate HTML template for password changed notification."""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Changed Successfully</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #28a745; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f8f9fa; }}
                .footer {{ padding: 20px; text-align: center; color: #666; font-size: 12px; }}
                .success {{ background-color: #d1edff; border: 1px solid #bee5eb; padding: 10px; border-radius: 4px; margin: 16px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{app_name}</h1>
                    <h2>Password Changed Successfully</h2>
                </div>
                <div class="content">
                    <p>Hello {username},</p>
                    <div class="success">
                        <strong>✓ Success!</strong> Your password has been changed successfully.
                    </div>
                    <p>If you didn't make this change, please contact our support team immediately.</p>
                    <p>For your security, we recommend:</p>
                    <ul>
                        <li>Using a strong, unique password</li>
                        <li>Enabling two-factor authentication if available</li>
                        <li>Keeping your account information up to date</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>This is an automated message from {app_name}. Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _get_password_changed_text_template(self, username: str, app_name: str) -> str:
        """Generate text template for password changed notification."""
        return f"""
{app_name} - Password Changed Successfully

Hello {username},

Your password has been changed successfully.

If you didn't make this change, please contact our support team immediately.

For your security, we recommend:
- Using a strong, unique password
- Enabling two-factor authentication if available
- Keeping your account information up to date

This is an automated message from {app_name}. Please do not reply to this email.
        """


# Global email service instance
email_service = EmailService()
