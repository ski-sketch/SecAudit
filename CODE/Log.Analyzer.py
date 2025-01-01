import logging
from logstash_async.handler import AsynchronousLogstashHandler

# Configure logging
logging.basicConfig(level=logging.INFO)

# Set up Logstash handler
host = 'localhost'
port = 5000
database_path = None

logger = logging.getLogger('python-logstash-logger')
logger.setLevel(logging.DEBUG)

async_handler = AsynchronousLogstashHandler(host, port, database_path=database_path)
logger.addHandler(async_handler)

def log_message(message):
    logger.info(message)

if __name__ == "__main__":
    while True:
        message = input("Enter a log message (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        log_message(message)
