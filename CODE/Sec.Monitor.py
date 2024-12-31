import asyncio
import logging
import os
import signal
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from configparser import ConfigParser
from datetime import datetime, timezone
from aiohttp import ClientSession

logging.basicConfig(level=logging.INFO)

# Load configuration
config = ConfigParser()
config.read('email_config.ini')

email_config = config['EMAIL']
smtp_server = email_config.get('smtp_server')
smtp_port = email_config.getint('smtp_port')
sender_email = email_config.get('email')
password = os.getenv('EMAIL_PASSWORD')  # Use environment variable for password
recipient_email = email_config.get('recipient_email', sender_email)  # Allow separate recipient email

# Validate email configuration
if not all([smtp_server, smtp_port, sender_email, password, recipient_email]):
    logging.error("Invalid email configuration. Please check email_config.ini and environment variables.")
    exit(1)

# Graceful shutdown
shutdown_event = asyncio.Event()

def shutdown_handler(signum, frame):
    logging.info("Shutdown signal received.")
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
            logging.info("Email sent successfully.")
            return
        except Exception as e:
            logging.error(f"Error sending email: {e}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

    logging.error("Failed to send email after multiple attempts.")

async def monitor():
    while not shutdown_event.is_set():
        try:
            async with ClientSession() as session:
                async with session.get('http://example.com/monitor') as response:
                    result = await response.json()
                    logging.info(f"Monitor result: {result}")
                    if 'vulnerability' in result:
                        await send_email("Vulnerability Alert", str(result))
        except Exception as e:
            logging.error(f"Error during monitoring: {e}")

        await asyncio.sleep(3600)  # Configurable interval

async def main():
    await monitor()

if __name__ == "__main__":
    asyncio.run(main())