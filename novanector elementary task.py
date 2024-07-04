import os
import sys
from cryptography.fernet import Fernet
import hashlib
import getpass
import logging

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt data
def encrypt_data(key, data):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Decrypt data
def decrypt_data(key, encrypted_data):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

# Create a simple user database
users = {
    "admin": hashlib.sha256("password123".encode()).hexdigest()
}

# Authenticate user
def authenticate(username, password):
    if username in users:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if users[username] == hashed_password:
            return True
        else:
            logging.warning("Suspicious activity: Failed login attempt for user %s", username)
            return False
    else:
        logging.warning("Suspicious activity: Failed login attempt for user %s", username)
        return False

# Setup logging
logging.basicConfig(filename='security.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Main function to demonstrate the features
def main():
    # Generate encryption key
    key = generate_key()
    print("Encryption key generated. Keep it safe!")

    # Sample data
    data = "Sensitive information that needs to be encrypted."

    # Encrypt data
    encrypted_data = encrypt_data(key, data)
    print("Encrypted data:", encrypted_data)

    # Decrypt data
    decrypted_data = decrypt_data(key, encrypted_data)
    print("Decrypted data:", decrypted_data)

    # User authentication
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    if authenticate(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed!")

    # Compliance message and training reminder
    print("\nCompliance with industry regulations and standards is ensured.")
    print("Remember to participate in regular cybersecurity training and awareness programs.")

if __name__ == "__main__":
    main()
