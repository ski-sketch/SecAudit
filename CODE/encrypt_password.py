import getpass
from cryptography.fernet import Fernet
from configparser import ConfigParser

# Prompt the user to input the actual password
actual_password = input("Enter the password you want to encrypt: ")

# Generate a key and encrypt the password
key = Fernet.generate_key()
cipher_suite = Fernet(key)
encrypted_password = cipher_suite.encrypt(actual_password.encode())

# Save the key and encrypted password to the config file
config = ConfigParser()
config['EMAIL'] = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': '587',
    'email': 'your_email@example.com',
    'recipient_email': 'recipient_email@example.com',
    'key': key.decode(),
    'password': encrypted_password.decode()
}

with open('email_config.ini', 'w') as configfile:
    config.write(configfile)

print("Password encrypted and saved to email_config.ini")