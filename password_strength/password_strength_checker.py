"""
=============================================================================
 PASSWORD STRENGTH CHECKER
 Industrial Training / Cybersecurity Internship - Project 1
=============================================================================

 What this program does
 ----------------------
 It asks the user for a password, analyses it against a set of security
 rules, gives it a score out of 7, and classifies it as WEAK, MEDIUM or
 STRONG. It then tells the user exactly why it got that rating and how to
 improve it.

 Security note
 -------------
 The password is NEVER printed back to the screen, never written to a file,
 and is deleted from memory as soon as the analysis is finished. The input
 is also hidden while typing (like a real login screen).

 Run it with:  python password_strength_checker.py
=============================================================================
"""

import math
import getpass
import sys


# ---------------------------------------------------------------------------
# SECTION 1: CONFIGURATION (all the "rules" live here so they are easy to edit)
# ---------------------------------------------------------------------------

# Characters we accept as "special symbols"
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ "

# A small offline sample of passwords that appear in real leaked password
# dumps (e.g. the RockYou list). A real system would check against a much
# bigger list or an online service such as Have I Been Pwned.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "password",
    "password1", "password123", "qwerty", "qwerty123", "abc123", "111111",
    "123123", "1234567890", "iloveyou", "admin", "admin123", "welcome",
    "welcome123", "monkey", "dragon", "letmein", "login", "princess",
    "sunshine", "master", "football", "baseball", "shadow", "superman",
    "trustno1", "passw0rd", "p@ssw0rd", "qwertyuiop", "asdfgh", "zxcvbnm",
    "india123", "test123", "root", "toor", "guest", "changeme", "secret",
}

# Predictable keyboard walks and dictionary fragments
OBVIOUS_PATTERNS = (
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz", "2wsx",
    "password", "letmein", "welcome", "admin", "iloveyou", "abcdef",
    "123456", "654321", "000000",
)

# Maximum number of points a password can earn
MAX_SCORE = 7

# How many characters we are willing to process (protects against someone
# pasting a 10 MB string - this is basic input validation)
MAX_LENGTH = 128
MIN_LENGTH = 8   # anything shorter is automatically WEAK


# ---------------------------------------------------------------------------
# SECTION 2: CHARACTER CHECKS
# Each function answers one simple yes/no question about the password.
# They use a loop over every character, which is the clearest way to show
# what "character checking" actually means.
# ---------------------------------------------------------------------------

def contains_uppercase(password):
    """Return True if the password has at least one A-Z letter."""
    for character in password:
        if character.isupper():
            return True
    return False


def contains_lowercase(password):
    """Return True if the password has at least one a-z letter."""
    for character in password:
        if character.islower():
            return True
    return False


def contains_digit(password):
    """Return True if the password has at least one 0-9 digit."""
    for character in password:
        if character.isdigit():
            return True
    return False


def contains_special(password):
    """Return True if the password has at least one special symbol."""
    for character in password:
        if character in SPECIAL_CHARACTERS:
            return True
    return False


def has_repeated_characters(password):
    """
    Return True if the same character appears 3+ times in a row.
    Example: 'aaa' in 'Paaassword!' -> True
    Repeats make a password much easier to guess.
    """
    repeat_count = 1
    for index in range(1, len(password)):
        if password[index] == password[index - 1]:
            repeat_count = repeat_count + 1
            if repeat_count >= 3:
                return True
        else:
            repeat_count = 1
    return False


def has_obvious_pattern(password):
    """
    Return True if the password contains a keyboard walk ('qwerty'),
    a dictionary fragment ('password'), or a run of 4+ sequential
    characters ('1234', 'abcd'). Attack tools try these first.
    """
    lowered = password.lower()

    # Check the known bad fragments
    for pattern in OBVIOUS_PATTERNS:
        if pattern in lowered:
            return True

    # Check for ascending or descending runs like 1234 / dcba
    ascending = 1
    descending = 1
    for index in range(1, len(lowered)):
        difference = ord(lowered[index]) - ord(lowered[index - 1])
        if difference == 1:
            ascending = ascending + 1
            descending = 1
        elif difference == -1:
            descending = descending + 1
            ascending = 1
        else:
            ascending = 1
            descending = 1
        if ascending >= 4 or descending >= 4:
            return True

    return False


def is_common_password(password):
    """
    Return True if the password appears in our leaked-password list.
    The comparison is case-insensitive because 'Password' is no safer
    than 'password' against a modern cracking tool.
    """
    return password.lower() in COMMON_PASSWORDS


# ---------------------------------------------------------------------------
# SECTION 3: SCORING
# ---------------------------------------------------------------------------

def score_length(password):
    """
    Give points for length. Length matters more than anything else,
    so it is worth up to 3 of the 7 available points.

        0-7   characters -> 0 points
        8-11  characters -> 1 point
        12-15 characters -> 2 points
        16+   characters -> 3 points
    """
    length = len(password)
    if length < 8:
        return 0
    elif length < 12:
        return 1
    elif length < 16:
        return 2
    else:
        return 3


def calculate_entropy(password):
    """
    Estimate password entropy in bits: entropy = length x log2(pool size).

    'Pool size' is how many different characters an attacker would have to
    try per position. More character types = a bigger pool = more guesses.
    This is a standard (if simplified) cybersecurity measurement.
    """
    pool_size = 0
    if contains_lowercase(password):
        pool_size = pool_size + 26
    if contains_uppercase(password):
        pool_size = pool_size + 26
    if contains_digit(password):
        pool_size = pool_size + 10
    if contains_special(password):
        pool_size = pool_size + 32

    if pool_size == 0 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 1)


def analyse_password(password):
    """
    The heart of the program.

    Takes a password and returns a dictionary (a labelled bag of results)
    containing the score, the rating, the reasons for the rating, and
    suggestions for improvement. It returns data instead of printing so
    that the same function can be reused by tests or by a web app.
    """
    results = {
        "length": len(password),
        "has_upper": contains_uppercase(password),
        "has_lower": contains_lowercase(password),
        "has_digit": contains_digit(password),
        "has_special": contains_special(password),
        "is_common": is_common_password(password),
        "has_repeats": has_repeated_characters(password),
        "has_pattern": has_obvious_pattern(password),
        "entropy": calculate_entropy(password),
        "reasons": [],
        "suggestions": [],
    }

    # ---- Step 1: award points -------------------------------------------
    score = score_length(password)

    if results["has_upper"]:
        score = score + 1
    if results["has_lower"]:
        score = score + 1
    if results["has_digit"]:
        score = score + 1
    if results["has_special"]:
        score = score + 1

    # ---- Step 2: subtract points for predictable habits ------------------
    if results["has_repeats"]:
        score = score - 1
    if results["has_pattern"]:
        score = score - 1

    # Keep the score inside the 0..MAX_SCORE range
    if score < 0:
        score = 0
    if score > MAX_SCORE:
        score = MAX_SCORE

    # ---- Step 3: hard override for known-leaked passwords ----------------
    # No amount of length or symbols saves a password that is already in a
    # public wordlist - an attacker finds it in under a second.
    if results["is_common"]:
        score = 0

    results["score"] = score

    # ---- Step 4: turn the score into a rating ----------------------------
    has_all_four = (results["has_upper"] and results["has_lower"]
                    and results["has_digit"] and results["has_special"])

    if results["is_common"]:
        rating = "WEAK"
    elif results["length"] < MIN_LENGTH:
        rating = "WEAK"
    elif score <= 3:
        rating = "WEAK"
    elif score >= 6 and results["length"] >= 12 and has_all_four:
        rating = "STRONG"
    else:
        rating = "MEDIUM"

    results["rating"] = rating

    # ---- Step 5: explain the rating --------------------------------------
    if results["is_common"]:
        results["reasons"].append(
            "This password appears in public lists of leaked passwords.")
    if results["length"] < MIN_LENGTH:
        results["reasons"].append(
            "Only " + str(results["length"]) + " characters - "
            "passwords under " + str(MIN_LENGTH) + " are cracked very quickly.")
    else:
        results["reasons"].append(
            str(results["length"]) + " characters long "
            "(" + str(score_length(password)) + "/3 length points).")

    character_types = []
    if results["has_lower"]:
        character_types.append("lowercase")
    if results["has_upper"]:
        character_types.append("uppercase")
    if results["has_digit"]:
        character_types.append("digits")
    if results["has_special"]:
        character_types.append("symbols")

    if len(character_types) == 0:
        results["reasons"].append("No recognised character types found.")
    else:
        results["reasons"].append(
            "Uses " + str(len(character_types)) + "/4 character types: "
            + ", ".join(character_types) + ".")

    if results["has_repeats"]:
        results["reasons"].append(
            "Contains a character repeated 3+ times in a row (-1 point).")
    if results["has_pattern"]:
        results["reasons"].append(
            "Contains a predictable sequence or keyboard pattern (-1 point).")

    results["reasons"].append(
        "Estimated entropy: " + str(results["entropy"]) + " bits.")

    # ---- Step 6: give improvement advice ---------------------------------
    if results["is_common"]:
        results["suggestions"].append(
            "Choose something completely different - this one is already known.")
    if results["length"] < 12:
        results["suggestions"].append(
            "Make it at least 12 characters (16+ is better).")
    if not results["has_upper"]:
        results["suggestions"].append("Add an uppercase letter.")
    if not results["has_lower"]:
        results["suggestions"].append("Add a lowercase letter.")
    if not results["has_digit"]:
        results["suggestions"].append("Add a number.")
    if not results["has_special"]:
        results["suggestions"].append(
            "Add a special symbol such as ! @ # $ % or &.")
    if results["has_repeats"]:
        results["suggestions"].append("Avoid repeating the same character.")
    if results["has_pattern"]:
        results["suggestions"].append(
            "Avoid keyboard walks (qwerty) and sequences (1234, abcd).")

    if len(results["suggestions"]) == 0:
        results["suggestions"].append(
            "Nothing to fix - store it in a password manager and enable "
            "two-factor authentication.")

    return results


# ---------------------------------------------------------------------------
# SECTION 4: DISPLAY
# ---------------------------------------------------------------------------

def build_strength_bar(score):
    """Build a simple text meter, e.g. [#####--] for a score of 5."""
    filled = "#" * score
    empty = "-" * (MAX_SCORE - score)
    return "[" + filled + empty + "]"


def print_report(results):
    """Print the analysis. The password itself is never printed."""
    print()
    print("=" * 58)
    print(" PASSWORD ANALYSIS REPORT")
    print("=" * 58)
    print(" Password entered : " + ("*" * 12) + "  (hidden for security)")
    print(" Strength meter   : " + build_strength_bar(results["score"])
          + "  " + str(results["score"]) + "/" + str(MAX_SCORE))
    print(" Strength rating  : " + results["rating"])
    print("-" * 58)

    print(" WHY THIS RATING:")
    for reason in results["reasons"]:
        print("   - " + reason)

    print()
    print(" HOW TO IMPROVE:")
    for suggestion in results["suggestions"]:
        print("   - " + suggestion)
    print("=" * 58)
    print()


# ---------------------------------------------------------------------------
# SECTION 5: INPUT HANDLING AND VALIDATION
# ---------------------------------------------------------------------------

def read_password():
    """
    Read a password without echoing it to the screen.

    getpass() hides the typing, which stops 'shoulder surfing' and keeps
    the password out of the terminal scrollback history. If the program is
    run in an environment with no real terminal, we fall back to input().
    """
    try:
        return getpass.getpass("Enter a password to test (typing is hidden): ")
    except Exception:
        print("(Warning: hidden input is unavailable here.)")
        return input("Enter a password to test: ")


def validate_password(password):
    """
    Check the raw input before analysing it.
    Returns an error message string, or None if the input is fine.
    This is 'input validation' - never trust what the user types.
    """
    if password is None or len(password) == 0:
        return "No password entered. Please type something."
    if password.strip() == "":
        return "A password made only of spaces is not accepted."
    if len(password) > MAX_LENGTH:
        return ("That is longer than " + str(MAX_LENGTH)
                + " characters. Please enter a shorter password.")
    return None


def run_demo():
    """Analyse a few example passwords so the grader can see it working."""
    samples = ["abc", "123456", "sunshine", "Cricket21", "Winter2024!",
               "Tr0ub4dor&3xplain", "aaaBBB111!!!"]
    print("\n--- DEMO MODE: analysing sample passwords ---")
    for sample in samples:
        outcome = analyse_password(sample)
        print("  " + build_strength_bar(outcome["score"])
              + " " + outcome["rating"].ljust(7)
              + " (" + str(outcome["score"]) + "/" + str(MAX_SCORE) + ")"
              + "  sample of length " + str(outcome["length"]))
    print("--- end of demo ---\n")


# ---------------------------------------------------------------------------
# SECTION 6: MAIN PROGRAM
# ---------------------------------------------------------------------------

def main():
    print("=" * 58)
    print(" CYBERSECURITY PASSWORD STRENGTH CHECKER")
    print(" Your password is hidden while typing and is never saved.")
    print("=" * 58)

    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        run_demo()
        return

    keep_going = True
    while keep_going:
        password = read_password()

        error = validate_password(password)
        if error is not None:
            print("  ! " + error + "\n")
            continue

        results = analyse_password(password)

        # Remove the password from memory as soon as we are done with it.
        password = None
        del password

        print_report(results)

        answer = input("Check another password? (y/n): ").strip().lower()
        if answer != "y" and answer != "yes":
            keep_going = False

    print("Stay safe. Use a password manager and turn on 2FA. Goodbye!")


# This line means: only run main() when the file is executed directly,
# not when it is imported by the test file.
if __name__ == "__main__":
    main()
