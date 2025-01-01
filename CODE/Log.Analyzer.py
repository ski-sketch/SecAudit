import logging
import os
import subprocess
from logstash_async.handler import AsynchronousLogstashHandler
from cryptography.fernet import Fernet

# Generate or load encryption key
encryption_key = os.getenv('ENCRYPTION_KEY')
if not encryption_key:
    encryption_key = Fernet.generate_key()
    print(f"Generated encryption key: {encryption_key.decode()}")
    os.environ['ENCRYPTION_KEY'] = encryption_key.decode()

# Define the relative path to the batch script
batch_script_path = os.path.join(os.path.dirname(__file__), 'run_log_analyzer.bat')

try:
    # Run the batch script to set environment variables
    subprocess.run(["cmd", "/c", batch_script_path], check=True)
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
    exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Set up Logstash handler using environment variables
host = os.getenv('LOGSTASH_HOST', 'logstash')
port = int(os.getenv('LOGSTASH_PORT', 5000))
database_path = None

logger = logging.getLogger('python-logstash-logger')
logger.setLevel(logging.DEBUG)

async_handler = AsynchronousLogstashHandler(host, port, database_path=database_path)
logger.addHandler(async_handler)

cipher_suite = Fernet(encryption_key)

def log_message(message):
    encrypted_message = cipher_suite.encrypt(message.encode())
    logger.info(encrypted_message.decode())

if __name__ == "__main__":
    while True:
        message = input("Enter a log message (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        log_message(message)