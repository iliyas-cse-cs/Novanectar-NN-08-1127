import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import hashlib
import logging

# Setup logging
logging.basicConfig(filename='security.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Caesar cipher encryption
def caesar_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted += chr((ord(char) - 97 + shift_amount) % 26 + 97)
            else:
                encrypted += chr((ord(char) - 65 + shift_amount) % 26 + 65)
        else:
            encrypted += char
    return encrypted

# Caesar cipher decryption
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

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

# GUI functions
def login():
    username = username_entry.get()
    password = password_entry.get()

    if authenticate(username, password):
        messagebox.showinfo("Login", "Authentication successful!")
        encryption_frame.pack(fill="both", expand=True)
    else:
        messagebox.showerror("Login", "Authentication failed!")

def encrypt_message():
    message = message_entry.get()
    shift = int(shift_entry.get())
    encrypted = caesar_encrypt(message, shift)
    messagebox.showinfo("Encrypted Message", f"Encrypted: {encrypted}")

def decrypt_message():
    encrypted_message = message_entry.get()
    shift = int(shift_entry.get())
    decrypted = caesar_decrypt(encrypted_message, shift)
    messagebox.showinfo("Decrypted Message", f"Decrypted: {decrypted}")

# GUI setup
root = tk.Tk()
root.title("Encryption and Authentication")

login_frame = tk.Frame(root)
login_frame.pack(fill="both", expand=True)

tk.Label(login_frame, text="Username").grid(row=0, column=0)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=0, column=1)

tk.Label(login_frame, text="Password").grid(row=1, column=0)
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1)

login_button = tk.Button(login_frame, text="Login", command=login)
login_button.grid(row=2, columnspan=2)

encryption_frame = tk.Frame(root)
tk.Label(encryption_frame, text="Message").grid(row=0, column=0)
message_entry = tk.Entry(encryption_frame)
message_entry.grid(row=0, column=1)

tk.Label(encryption_frame, text="Shift").grid(row=1, column=0)
shift_entry = tk.Entry(encryption_frame)
shift_entry.grid(row=1, column=1)

encrypt_button = tk.Button(encryption_frame, text="Encrypt", command=encrypt_message)
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(encryption_frame, text="Decrypt", command=decrypt_message)
decrypt_button.grid(row=2, column=1)

root.mainloop()
