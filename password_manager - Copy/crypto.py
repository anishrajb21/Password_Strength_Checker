import os
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_FILE = os.path.join(DATA_DIR, ".key")


def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)


def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()

    try:
        key = open(KEY_FILE, "rb").read()
        Fernet(key)  # validate key
        return key

    except:
        print("Invalid key detected. Generating new key...")
        generate_key()
        return open(KEY_FILE, "rb").read()


def get_fernet():
    return Fernet(load_key())