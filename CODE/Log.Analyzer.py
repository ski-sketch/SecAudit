import logging
import os
import socket
from logstash_async.handler import AsynchronousLogstashHandler
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('python-logstash-logger')
logger.setLevel(logging.DEBUG)

def is_logstash_running(host, port):
    """Check if Logstash service is up and running."""
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (OSError, socket.timeout) as e:
        logger.error(f"Error checking Logstash service: {e}")
        return False

# Generate or load encryption key
encryption_key = os.getenv('ENCRYPTION_KEY')
if not encryption_key:
    try:
        encryption_key = Fernet.generate_key()
        print(f"Generated encryption key: {encryption_key.decode()}")
        os.environ['ENCRYPTION_KEY'] = encryption_key.decode()
        # Write the key to a file
        with open('encryption_key.txt', 'w') as key_file:
            key_file.write(encryption_key.decode())
    except Exception as e:
        logger.error(f"Failed to generate or save encryption key: {e}")
        exit(1)

# Set environment variables
os.environ['LOGSTASH_HOST'] = '127.0.0.1'  # Use the IP address of the Logstash container
os.environ['LOGSTASH_PORT'] = '5000'

# Set up Logstash handler using environment variables
host = os.getenv('LOGSTASH_HOST', '127.0.0.1')
port = int(os.getenv('LOGSTASH_PORT', 5000))
database_path = None

if is_logstash_running(host, port):
    try:
        async_handler = AsynchronousLogstashHandler(host, port, database_path=database_path)
        logger.addHandler(async_handler)
    except Exception as e:
        logger.error(f"Failed to set up Logstash handler: {e}")
        exit(1)
else:
    logger.error("Logstash service is not running. Please start the Logstash service and try again.")
    exit(1)

cipher_suite = Fernet(encryption_key)

def log_message(message):
    try:
        encrypted_message = cipher_suite.encrypt(message.encode())
        logger.info(encrypted_message.decode())
    except (TypeError, ValueError) as e:
        logger.error(f"Encryption error: {e}")
    except Exception as e:
        logger.error(f"Failed to log message: {e}")

if __name__ == "__main__":
    while True:
        try:
            message = input("Enter a log message (or 'quit' to exit): ")
            if message.lower() == 'quit':
                break
            log_message(message)
        except KeyboardInterrupt:
            logger.info("Program interrupted by user.")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")