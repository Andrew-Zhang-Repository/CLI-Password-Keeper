import base64, os, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import os

CONFIG_FILE = "config.json"
QUESTION_FILE = "question.json"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from master password + salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def recovery_mode():
    if not os.path.exists(QUESTION_FILE):
        print("No recovery questions set.")
        return
    
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
        salt = base64.b64decode(config["salt"])
    
    with open(QUESTION_FILE, "r") as f:
        stored_qas = json.load(f)

    print("Answer a series of your own verification questions")

    total_correct = 0
    for key,ans in stored_qas.items():

        print(key)
        answer = input("Your answer? ").strip().lower()

        decrypted_answer = hashlib.sha256(answer.encode()).hexdigest()
            
        if decrypted_answer == ans:
            total_correct +=1

    if total_correct >=2:
        print("Your allowed change master password now while keeping your password vault")
        set_master_key()

    else:
        print("Verification failure")



def set_master_key():

    with open(CONFIG_FILE, 'w') as f:
        json.dump({}, f)

    password = input("Create master password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    master_hash = hashlib.sha256(password.encode()).hexdigest()


    with open(CONFIG_FILE, "w") as f:
        
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "master_hash": master_hash
        }, f)

    print("Master password created successfully.")
    print("Now you will set a 3 questions yourself that only you would know. In case you forget your master key")

    question_and_answer = {}

    for i in range(0,3):

        verified = False
        
        while (verified == False):
            question = input("Type your question: ")
            answer = input("Now type the answer to that question: ").strip().lower()
        

            if question not in question_and_answer:
                question_and_answer[question] = hashlib.sha256(answer.encode()).hexdigest()
                verified = True
            else:
                print("You have already inputted that question, try again")


    # Put question a json file/encrypted file dk whats optimal here

    
    with open(QUESTION_FILE, "w") as f:
        json.dump(question_and_answer, f, indent=4)

    return key

           




def setup_master_password():
    
    if not os.path.exists(CONFIG_FILE):
        empty_data = {}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(empty_data, f)

    with open(CONFIG_FILE,'r') as f:
        config = json.load(f)

        if "salt" in config and "master_hash" in config:
            print("master key has already been created")
            print("activate forgot password or override?")
            print("override will delete all kept passwords from last master key")

            option = input("Forgot? or Override?:\n")

            if option == "Forgot":
                
                
                recovery_mode()
                return None
            elif option == "Override":
                with open(CONFIG_FILE, 'w') as f:
                    json.dump({}, f)
                # Remove vaulted password lists
            else:
                print("invalid option")

        else:

            
            return Fernet(set_master_key())

def load_master_password():
    
    if not os.path.exists(CONFIG_FILE):
        print("No master key created yet")
        return None
    
    with open(CONFIG_FILE,'r') as f:
        config = json.load(f)
        if "salt" not in config and "master_hash" not in config:
            print("No master key created yet")
            return None
        
       

    
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    password = input("Enter master password: ")
    entered_hash = hashlib.sha256(password.encode()).hexdigest()

    if entered_hash != config["master_hash"]:
        print("Incorrect master key.")
        return None
    else:
        print("Correct master key")
        # add new password to lists function
    


    salt = base64.b64decode(config["salt"])
    key = derive_key(password, salt)
    return Fernet(key)


def main():
    print("options key:\n 1 : create master key, 2 : enter master key")
    option = input()
    
    while True:
        if option == "1":
            setup_master_password()
            break

           
        elif option == "2":
            load_master_password()
            break

        else:
            print("invalid option")
            break


if __name__ == "__main__":
    main()