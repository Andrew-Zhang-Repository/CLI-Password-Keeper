import base64, os, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import vault_management
import hashlib
import os

CONFIG_FILE = "config.json"
QUESTION_FILE = "question.json"
VAULT = "vault.json"

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
        recovery_salt = base64.b64decode(config["recovery_salt"])
    
    with open(QUESTION_FILE, "r") as f:
        stored_qas = json.load(f)

    print("Answer a series of your own verification questions")

    total_correct = 0
    correct_answers = []
    for key,ans in stored_qas.items():

        print(key)
        answer = input("Your answer? ").strip().lower()

        decrypted_answer = hashlib.sha256(answer.encode()).hexdigest()
            
        if decrypted_answer == ans:
            correct_answers.append(answer)
            total_correct +=1

    if total_correct ==3:
        print("\nYou're allowed change master password now while keeping your password vault\n")

        recovery_key = derive_key("".join(correct_answers), recovery_salt)
        recovery_fernet = Fernet(recovery_key)
        encrypted_master = config["encrypted_master_password"]
        old_master_key = recovery_fernet.decrypt(encrypted_master.encode()).decode()
    
        old_pass = Fernet(derive_key(old_master_key, salt))
        #rencrypt here
        set_master_key(old_pass)
       

    else:
        print("Verification failure")






def set_master_key(old):

    if os.path.exists(VAULT) == False:
        print("Add some passwords before considering a pass change")
        return

    
    password = input("Create master password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    master_hash = hashlib.sha256(password.encode()).hexdigest()
    encrypted_key = Fernet(key)

    # potential rencrypt

    if old != None:
        old_passes = []
        with open(VAULT,"r") as fv:
            data = json.load(fv)
        
        if not data == False or data == None:
            for i in data:
                og_desc = vault_management.decrypt_password(old,i["description"])
                og_user = vault_management.decrypt_password(old,i["username"])
                og_password = vault_management.decrypt_password(old,i["password"])

           
                new_desc = vault_management.encrypt_password(encrypted_key,og_desc)
                new_user = vault_management.encrypt_password(encrypted_key,og_user)
                new_pass = vault_management.encrypt_password(encrypted_key,og_password)

                old_passes.append({"description":new_desc,"username":new_user,"password":new_pass})
        
        if os.path.exists(VAULT):
            with open(VAULT,"w") as fm:
                json.dump(old_passes,fm)



    print("\nMaster password created successfully.")
    print("\nNow you will set a 3 questions yourself that only you would know. In case you forget your master key\n")

    question_and_answer = {}
    answers = []
    for i in range(0,3):

        verified = False
        
        while (verified == False):
            question = input("Type your question: ")
            answer = input("Now type the answer to that question: ").strip().lower()
        

            if question not in question_and_answer:
                question_and_answer[question] = hashlib.sha256(answer.encode()).hexdigest()
                answers.append(answer)
                verified = True
            else:
                print("You have already inputted that question, try again")

    recovery_salt = os.urandom(16)
    recovery_key = derive_key("".join(answers), recovery_salt)
    recovery_fernet = Fernet(recovery_key)
    encrypted_master_password = recovery_fernet.encrypt(password.encode()).decode()

    with open(CONFIG_FILE, 'w') as f:
        json.dump({}, f)

    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "recovery_salt": base64.b64encode(recovery_salt).decode(),
            "master_hash": master_hash,
            "encrypted_master_password": encrypted_master_password
        }, f)
  
    
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
            print("Master key has already been created\n")
            print("Activate forgot password or override?\n")
            print("Override will delete all kept passwords from last master key\n")

            option = input("Forgot? or Override? or Go Back?(press anything):\n")

            if option == "Forgot":
                
                recovery_mode()
                return None
            
            elif option == "Override":
                with open(CONFIG_FILE, 'w') as f:
                    json.dump({}, f)
                
                if os.path.exists(VAULT) == True:
                    with open(VAULT, 'w') as f:
                        json.dump([], f)

                if os.path.exists(QUESTION_FILE) == True:
                    with open(QUESTION_FILE,"w") as f:  
                        json.dump({},f)  
            else:
                return None

        else:

            
            return Fernet(set_master_key(None))

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
        if os.path.exists(VAULT) == False:
            with open(VAULT,"w") as f: 
                json.dump([], f)
        print("You have entered the correct master key\n")
      

        salt = base64.b64decode(config["salt"])
        key = derive_key(password, salt)
        object =  Fernet(key)


        
        vault_management.cli_interface(object)


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

    return


if __name__ == "__main__":
    stop = False

    while stop == False:
        main()

        halt = input("Stop program? Type yes or no\n")

        if halt == "yes":
            stop = True  
        else:
            stop = False