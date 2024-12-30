import asyncio
import smtplib
from email.mime.text import MIMEText
from subprocess import run
from datetime import datetime

async def run_scan():
    try:
        result = run(['python3', 'Vuln.Scan.py'], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running scan: {str(e)}"

async def send_alert(message, recipient_email):
    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Security Alert'
        msg['From'] = 'your_email@example.com'
        msg['To'] = recipient_email

        with smtplib.SMTP('smtp.example.com') as server:
            server.login('your_email@example.com', 'your_password')
            server.sendmail('your_email@example.com', [recipient_email], msg.as_string())
    except Exception as e:
        print(f"Error sending alert: {str(e)}")

async def monitor(recipient_email):
    while True:
        print(f"Running scan at {datetime.now()}")
        scan_result = await run_scan()
        if "vulnerability" in scan_result.lower():
            await send_alert(f"Vulnerability detected:\n{scan_result}", recipient_email)
        await asyncio.sleep(3600)  # Run every hour

async def main():
    recipient_email = input("Please enter your email address: ")
    await monitor(recipient_email)

if __name__ == '__main__':
    asyncio.run(main())