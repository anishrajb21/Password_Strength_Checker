import random
import string
import re


def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_+=<>?"
    return ''.join(random.choice(chars) for _ in range(length))


def check_strength(password):

    score = 0

    if len(password) >= 8:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1

    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"[0-9]", password):
        score += 1

    if re.search(r"[!@#$%^&*()_+=<>?]", password):
        score += 1

    if score <= 2:
        return "Weak"

    elif score <= 4:
        return "Medium"

    else:
        return "Strong"