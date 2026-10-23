
import sqlite3
from getpass import getpass
from argon2 import PasswordHasher

DATABASE_NAME = "../database/crypto_pro.db"

username = "jhansi"
password = getpass("Enter your new password: ")
confirm_password = getpass("Confirm your new password: ")

if not password:
    print("Password cannot be empty.")
elif password != confirm_password:
    print("Passwords do not match. Try again.")
else:
    password_hash = PasswordHasher().hash(password)

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (password_hash, username)
    )

    connection.commit()

    if cursor.rowcount == 1:
        print("Password reset successfully!")
    else:
        print("User not found. No password was changed.")

    connection.close()