import json
import os
from crypto import get_fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
VAULT_FILE = os.path.join(DATA_DIR, ".vault.json")


# 🔥 FIXED FUNCTION (IMPORTANT)
def load_data():
    if not os.path.exists(VAULT_FILE):
        return {}

    try:
        with open(VAULT_FILE, "r") as f:
            content = f.read().strip()

            # If file is empty → return empty dict
            if not content:
                return {}

            return json.loads(content)

    except:
        # If file is corrupted → reset safely
        return {}


def save_data(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4)


def save_password(platform, username, password):
    fernet = get_fernet()
    data = load_data()

    if platform not in data:
        data[platform] = {}

    data[platform][username] = fernet.encrypt(password.encode()).decode()
    save_data(data)


def list_all():
    data = load_data()

    if not data:
        print("No data found.")
        return

    for p, users in data.items():
        print(f"\n{p}")
        for u, pwd in users.items():
            print(f"  {u} -> {pwd}")


def list_platform(platform):
    data = load_data()

    if platform in data:
        for u, pwd in data[platform].items():
            print(f"{u} -> {pwd}")
    else:
        print("Platform not found.")


def decrypt_all():
    fernet = get_fernet()
    data = load_data()

    if not data:
        print("No data found.")
        return

    for p, users in data.items():
        print(f"\n{p}")
        for u, enc in users.items():
            print(f"{u} -> {fernet.decrypt(enc.encode()).decode()}")


def decrypt_platform(platform):
    fernet = get_fernet()
    data = load_data()

    if platform in data:
        for u, enc in data[platform].items():
            print(f"{u} -> {fernet.decrypt(enc.encode()).decode()}")
    else:
        print("Platform not found.")


def decrypt_single(platform, user):
    fernet = get_fernet()
    data = load_data()

    try:
        enc = data[platform][user]
        print("Password:", fernet.decrypt(enc.encode()).decode())
    except:
        print("User or platform not found.")


def update_password(platform, username, new_password):
    save_password(platform, username, new_password)


def delete_user(platform, username):
    data = load_data()

    try:
        del data[platform][username]
        save_data(data)
        print("User deleted.")
    except:
        print("User not found.")


def delete_platform(platform):
    data = load_data()

    if platform in data:
        del data[platform]
        save_data(data)
        print("Platform deleted.")
    else:
        print("Platform not found.")