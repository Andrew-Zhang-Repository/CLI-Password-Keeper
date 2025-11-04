import json
import os

VAULT = "vault.json"

def encrypt_password(fernet, password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

def add_password(fernet):
    print("\nPlease type in this format : Description->Username->Password\n")


    stop = False

    while stop == False:
        desc = input("Enter description: ")
        user = input("Enter username: ")
        password = input("Enter password: ").strip()

        enc_pass = encrypt_password(fernet,password)
        enc_desc = encrypt_password(fernet,desc)
        enc_user = encrypt_password(fernet,user)

        new_entry = {
            "description": enc_desc,
            "username": enc_user,
            "password": enc_pass
        }

        
        if os.path.exists(VAULT):
            with open(VAULT, "r") as f:
                data = json.load(f)
        else:
            data = []

        data.append(new_entry)

        with open(VAULT, "w") as f:
            json.dump(data, f)

        halt = input("Type stop to terminate adding process else type no\n")

        if halt == "stop":
            stop = True
        else:
            # Do nothing or continue
            stop = False


    print("\nPassword saved securely.")


def show_pass_list(fernet):

    with open(VAULT,"r") as f:
        data = json.load(f)

    for i in data:

        print("DESCRIPTION: ")
        print(decrypt_password(fernet, i["description"])+"\n")

        print("USERNAME: ")
        print(decrypt_password(fernet, i["username"]) + "\n")

        print("PASSWORD: ")
        print(decrypt_password(fernet, i["password"])+ "\n")

        print("\n\n")


    print("All has been displayed")


def cli_interface(fernet):
    

    print("You are now in.\n\nType 1 to show current passwords and their desc\n" \
    "Type 2 to add a password along with a description")

    answer = input("\nWhat do you wish to do?\n")

    while True:
        if answer == "1":
            
            
            show_pass_list(fernet)

            stop = False
            while stop == False:
                halt = input("You will be prompted to go back to menu press yes\n")

                if halt == "yes":
                    stop = True
                
            break
        elif answer == "2":
            add_password(fernet)
            break
        else:
            print("Invalid entry ")
            break
    

