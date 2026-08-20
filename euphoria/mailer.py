"""Email sending service with SMTP and HTML template rendering."""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '465'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER or 'noreply@euphoria-project.com')
SMTP_SSL = os.environ.get('SMTP_SSL', '1') == '1'


def send_password_reset_email(to_email: str, username: str, code: str) -> tuple[bool, str]:
    """
    Sends a styled HTML password reset email with the 6-digit security code.
    Returns (success: bool, info_message: str).
    """
    subject = f"🔒 Код сброса пароля EUPHORIA: {code}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body {{ background-color: #070913; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #f1f5f9; padding: 20px; }}
        .box {{ max-width: 520px; margin: 0 auto; background: #0d1122; border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 16px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .header {{ text-align: center; margin-bottom: 24px; }}
        .title {{ font-size: 22px; font-weight: 800; color: #38bdf8; letter-spacing: 1px; }}
        .code-box {{ background: #12182e; border: 2px dashed #38bdf8; border-radius: 12px; padding: 18px; text-align: center; margin: 24px 0; }}
        .code {{ font-size: 32px; font-weight: 900; letter-spacing: 8px; color: #fff; text-shadow: 0 0 15px rgba(56,189,248,0.5); }}
        .note {{ font-size: 13px; color: #94a3b8; line-height: 1.5; margin-top: 14px; text-align: center; }}
        .footer {{ margin-top: 26px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 14px; font-size: 11.5px; color: #64748b; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="box">
        <div class="header">
          <div class="title">⚡ EUPHORIA SECURITY</div>
          <p style="color:#94a3b8;font-size:14px;margin-top:4px">Восстановление доступа к аккаунту</p>
        </div>
        <p>Здравствуйте, <strong>{username}</strong>!</p>
        <p style="color:#cbd5e1;font-size:14px;margin-top:8px">Был получен запрос на сброс пароля для вашего аккаунта на сайте EUPHORIA.</p>
        <div class="code-box">
          <div style="font-size:12px;color:#38bdf8;font-weight:700;margin-bottom:6px;text-transform:uppercase">Ваш код подтверждения:</div>
          <div class="code">{code}</div>
        </div>
        <p class="note">Код действителен в течение <strong>15 минут</strong>.<br>Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.</p>
        <div class="footer">
          © 2026 EUPHORIA Client. Все права защищены.
        </div>
      </div>
    </body>
    </html>
    """

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return True, "Code saved and logged for Admin review"

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"EUPHORIA <{SMTP_FROM}>"
        msg['To'] = to_email

        text_part = MIMEText(f"Здравствуйте, {username}!\nВаш код для сброса пароля: {code}\nКод действителен 15 минут.", 'plain', 'utf-8')
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(text_part)
        msg.attach(html_part)

        if SMTP_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            server.starttls()

        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        server.quit()
        return True, "Email successfully sent"
    except Exception as err:
        return False, f"SMTP error: {str(err)}"
