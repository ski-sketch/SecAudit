import asyncio
import smtplib
from email.mime.text import MIMEText
from subprocess import run
from datetime import datetime
import re
import logging
import configparser

logging.basicConfig(level=logging.INFO)

def load_email_config(filename="email_config.ini"):
    config = configparser.ConfigParser()
    try:
        config.read(filename)
        email_config = {
            "smtp_server": config.get("EMAIL", "smtp_server"),
            "smtp_port": config.getint("EMAIL", "smtp_port"),
            "email": config.get("EMAIL", "email"),
            "password": config.get("EMAIL", "password")
        }
        return email_config
    except Exception as e:
        logging.error(f"Error loading email configuration: {e}")
        return None

async def run_scan():
    try:
        result = run(['python3', 'Vuln.Scan.py'], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        logging.error(f"Error running scan: {e}")
        return f"Error running scan: {str(e)}"

async def send_alert(message, recipient_email, email_config):
    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Security Alert'
        msg['From'] = email_config['email']
        msg['To'] = recipient_email

        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            server.starttls()
            server.login(email_config['email'], email_config['password'])
            server.sendmail(email_config['email'], [recipient_email], msg.as_string())
        logging.info(f"Alert sent to {recipient_email}")
    except Exception as e:
        logging.error(f"Error sending alert to {recipient_email}: {e}")

async def monitor(email_config):
    recipient_email = email_config['email']
    while True:
        logging.info(f"Running scan at {datetime.now()}")
        scan_result = await run_scan()
        if "vulnerability" in scan_result.lower():
            await send_alert(f"Vulnerability detected:\n{scan_result}", recipient_email, email_config)
        await asyncio.sleep(3600)  # Run every hour

async def main():
    email_config = load_email_config()
    if not email_config:
        logging.error("Failed to load email configuration. Exiting.")
        return

    await monitor(email_config)

if __name__ == '__main__':
    asyncio.run(main())