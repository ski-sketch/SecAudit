import asyncio
import logging
import os
import signal
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from configparser import ConfigParser
from aiohttp import ClientSession
import colorlog

# Configure logging
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(levelname)s: %(message_log_color)s%(message)s",
    log_colors={
        'INFO': 'green',
        'ERROR': 'red',
    },
    secondary_log_colors={
        'message': {
            'INFO': 'blue',
            'ERROR': 'blue',
        }
    }
))

logger = colorlog.getLogger('web-monitor')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load email configuration
email_config = ConfigParser()
email_config.read('email_config.ini')

email_settings = email_config['EMAIL']
smtp_server = email_settings.get('smtp_server')
smtp_port = email_settings.getint('smtp_port')
sender_email = email_settings.get('email')
password = os.getenv('EMAIL_PASSWORD')  # Use environment variable for password
recipient_email = email_settings.get('recipient_email', sender_email)  # Allow separate recipient email

# Load website URL configuration
url_config = ConfigParser()
url_config.read('web_url_config.ini')

website_url = url_config['WEBSITE'].get('url')

# Validate configurations
if not all([smtp_server, smtp_port, sender_email, password, recipient_email, website_url]):
    logger.error("Invalid configuration. Please check email_config.ini, web_url_config.ini, and environment variables.")
    exit(1)

# Graceful shutdown
shutdown_event = asyncio.Event()

def shutdown_handler(signum, frame):
    logger.info("Shutdown signal received.")
    shutdown_event.set()

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

async def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    for attempt in range(3):  # Retry mechanism
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, password)
                server.sendmail(sender_email, recipient_email, msg.as_string())
            logger.info("Email sent successfully.")
            return
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

    logger.error("Failed to send email after multiple attempts.")

async def monitor():
    while not shutdown_event.is_set():
        try:
            async with ClientSession() as session:
                async with session.get(website_url) as response:
                    result = await response.json()
                    logger.info(f"Monitor result: {result}")
                    if 'vulnerability' in result:
                        await send_email("Vulnerability Alert", str(result))
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")

        await asyncio.sleep(3600)  # Configurable interval

async def main():
    await monitor()

if __name__ == "__main__":
    asyncio.run(main())