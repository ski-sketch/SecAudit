import asyncio
import logging
import signal
import smtplib
from configparser import ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from aiohttp import ClientSession
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO)

# Load configuration
config = ConfigParser()
config.read('email_config.ini')

email_config = config['EMAIL']
smtp_server = email_config.get('smtp_server')
smtp_port = email_config.getint('smtp_port')
sender_email = email_config.get('email')
recipient_email = email_config.get('recipient_email', sender_email)  # Allow separate recipient email

# Decrypt the password
key = email_config.get('key').encode()
encrypted_password = email_config.get('password').encode()
cipher_suite = Fernet(key)
password = cipher_suite.decrypt(encrypted_password).decode()

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
                    if response.status == 200 and response.content_type == 'application/json':
                        result = await response.json()
                        logging.info(f"Monitor result: {result}")
                        if 'vulnerability' in result:
                            await send_email("Vulnerability Alert", str(result))
                    else:
                        logging.error(f"Unexpected response: {response.status}, content type: {response.content_type}")
        except Exception as e:
            logging.error(f"Error during monitoring: {e}")

        await asyncio.sleep(3600)  # Configurable interval

async def main():
    await monitor()

if __name__ == "__main__":
    asyncio.run(main())