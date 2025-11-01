import base64, os, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import os

VAULT = "vault.json"
# Assuming fernet is already created from master password
def encrypt_password(fernet, password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

def add_password(fernet):
    print("Please type in this format : Description->Username->Password")

    desc = input("Enter description: ")
    user = input("Enter username: ")
    password = input("Enter password: ").strip()

    enc_pass = encrypt_password(fernet,password)

    new_entry = {
        "description": desc,
        "username": user,
        "password": enc_pass
    }

    # Load existing passwords
    if os.path.exists(VAULT):
        with open(VAULT, "r") as f:
            data = json.load(f)
    else:
        data = []

    data.append(new_entry)

    with open(VAULT, "w") as f:
        json.dump(data, f)

    print("Password saved securely.")






def cli_interface(fernet):
    

    print("You are now in.\n Type 1 to show current passwords and their desc\n" \
    "Type 2 to add a password along with a description")

    answer = input("What do you wish to do ? ")

    while True:
        if answer == "1":
            # Show pass word list
            break
        elif answer == "2":
            add_password(fernet)
            break
        else:
            print("Invalid entry ")
    

