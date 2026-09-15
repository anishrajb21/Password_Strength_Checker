import os

from auth import verify_password, change_master_password

from generator import (
    generate_password,
    check_strength
)

from manager import *

from export_pdf import export_pdf


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(DATA_DIR, exist_ok=True)


def menu():

    print("\n1. Generate Password")
    print("2. List")
    print("3. Modify")
    print("4. Delete")
    print("5. Reveal Passwords")
    print("6. Change Master Password")
    print("7. Export PDF")
    print("8. Exit")


# ---------------- LIST MENU ----------------

def list_menu():

    while True:

        print("\n1. List All")
        print("2. List Specific Platform")
        print("3. Back")

        choice = input("Choice: ")

        if choice == "1":

            list_all()

        elif choice == "2":

            p = input("Platform: ")

            list_platform(p)

        elif choice == "3":

            return

        else:

            print("Invalid choice.")


# ---------------- DELETE MENU ----------------

def delete_menu():

    while True:

        print("\n1. Delete User")
        print("2. Delete Platform")
        print("3. Back")

        choice = input("Choice: ")

        if choice == "1":

            p = input("Platform: ")
            u = input("Username: ")

            delete_user(p, u)

        elif choice == "2":

            p = input("Platform: ")

            delete_platform(p)

        elif choice == "3":

            return

        else:

            print("Invalid choice.")


# ---------------- REVEAL MENU ----------------

def reveal_menu():

    while True:

        print("\n1. View ALL passwords")
        print("2. View platform passwords")
        print("3. View single user password")
        print("4. Back")

        choice = input("Choice: ")

        if choice == "1":

            if verify_password():

                decrypt_all()

        elif choice == "2":

            p = input("Platform: ")

            if verify_password():

                decrypt_platform(p)

        elif choice == "3":

            p = input("Platform: ")
            u = input("Username: ")

            if verify_password():

                decrypt_single(p, u)

        elif choice == "4":

            return

        else:

            print("Invalid choice.")


# ---------------- MODIFY MENU ----------------

def modify_menu():

    while True:

        print("\n1. Modify Password")
        print("2. Back")

        choice = input("Choice: ")

        if choice == "1":

            p = input("Platform: ")
            u = input("Username: ")

            new_pwd = generate_password(12)

            update_password(p, u, new_pwd)

            print("Updated Password:", new_pwd)

        elif choice == "2":

            return

        else:

            print("Invalid choice.")


# ---------------- ADD EXISTING PASSWORD ----------------

def add_existing_password():

    platform = input("Platform: ")
    username = input("Username: ")

    existing_password = input(
        "Enter Existing Password: "
    )

    strength = check_strength(existing_password)

    print("Password Strength:", strength)

    if strength == "Weak":

        choice = input(
            "Weak password detected. "
            "Generate strong password? yes/no: "
        ).lower()

        if choice == "yes":

            try:

                length = int(
                    input("Enter password length: ")
                )

                if length < 4:

                    print("Length too short.")
                    return

            except:

                print("Invalid length.")
                return

            existing_password = generate_password(length)

            print(
                "Generated Password:",
                existing_password
            )

    save_password(
        platform,
        username,
        existing_password
    )

    print("Password saved successfully.")


# ---------------- GENERATE MENU ----------------

def generate_menu():

    while True:

        print("\n1. Generate Password")
        print("2. Add Existing Password")
        print("3. Back")

        choice = input("Choice: ")

        if choice == "1":

            p = input("Platform: ")
            u = input("Username: ")

            try:

                length = int(
                    input("Enter password length: ")
                )

                if length < 4:

                    print(
                        "Length should be at least 4."
                    )

                    continue

            except:

                print("Invalid length.")

                continue

            pwd = generate_password(length)

            print("Generated:", pwd)

            if input(
                "Save? yes/no: "
            ).lower() == "yes":

                save_password(p, u, pwd)

                print("Saved successfully.")

        elif choice == "2":

            add_existing_password()

        elif choice == "3":

            return

        else:

            print("Invalid choice.")


# ---------------- MAIN ----------------

def main():

    if not verify_password():

        return

    while True:

        menu()

        ch = input("Choice: ")

        if ch == "1":

            generate_menu()

        elif ch == "2":

            list_menu()

        elif ch == "3":

            modify_menu()

        elif ch == "4":

            delete_menu()

        elif ch == "5":

            reveal_menu()

        elif ch == "6":

            change_master_password()

        elif ch == "7":

            export_pdf()

        elif ch == "8":

            break

        else:

            print("Invalid choice.")


if __name__ == "__main__":

    main()