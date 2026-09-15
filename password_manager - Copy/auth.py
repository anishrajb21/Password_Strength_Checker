import hashlib
import os
import getpass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
AUTH_FILE = os.path.join(DATA_DIR, ".auth")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def setup_password():
    while True:
        pwd1 = getpass.getpass("Set Master Password: ")
        pwd2 = getpass.getpass("Confirm Password: ")

        if pwd1 != pwd2:
            print("Passwords do not match.\n")
        elif len(pwd1) < 6:
            print("Password too short.\n")
        else:
            with open(AUTH_FILE, "w") as f:
                f.write(hash_password(pwd1))
            print("Master password set.\n")
            break

def verify_password():
    if not os.path.exists(AUTH_FILE):
        setup_password()

    stored = open(AUTH_FILE).read()

    for i in range(3):
        pwd = getpass.getpass("Enter Master Password: ")
        if hash_password(pwd) == stored:
            return True
        else:
            print(f"Wrong! Attempts left: {2-i}")
    return False

# 🔥 NEW FEATURE
def change_master_password():
    stored = open(AUTH_FILE).read()

    current = getpass.getpass("Enter current password: ")
    if hash_password(current) != stored:
        print("Wrong current password.")
        return

    new1 = getpass.getpass("Enter new password: ")
    new2 = getpass.getpass("Confirm new password: ")

    if new1 != new2:
        print("Passwords do not match.")
        return

    with open(AUTH_FILE, "w") as f:
        f.write(hash_password(new1))

    print("Master password updated.")