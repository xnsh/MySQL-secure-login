"""
loginhashing.py - Simple login / registration system backed by MySQL.

How it works:
  - The MySQL root password is read from a separate file (secure.txt), so the
    source code can be shared without leaking the password.
  - Register: the user picks a username and password. The password is hashed
    with PBKDF2-HMAC-SHA256 and a random salt. Only "salt$hash" is stored.
  - Login: the stored salt is used to hash the entered password the same way,
    then the two hashes are compared. Same hash = correct password.
"""

import hashlib
import hmac
import os
from getpass import getpass
import mysql.connector

# Pulls password for MySQL server from another file.. Code could be open source this way.
# strip() removes the trailing newline most editors add, which would break the login.
with open("secure.txt", "r") as fb:
    serverpassword = fb.read().strip()

# PBKDF2 runs SHA-256 many times, so each guess is slow for an attacker
ITERATIONS = 600_000


def hash_function(text, salt=None):
    """Hash text with PBKDF2-HMAC-SHA256. Return "salt$hash" (both hex).

    A new random salt is made when none is given (register). At login, pass
    the stored salt so the same password gives the same hash.
    """
    if salt is None:
        salt = os.urandom(16).hex()      # random salt, unique per user
    hash = hashlib.pbkdf2_hmac("sha256", text.encode(), bytes.fromhex(salt), ITERATIONS).hex()

    return salt + "$" + hash

def createAccount():
    """Ask for a new username and password. Return (username, password_hash)."""
    user = input("Enter desired username:  ")
    pswd = getpass("Set password: ")     # hidden while typing

    login = (user, hash_function(pswd))   # never keep the plain password

    return login

def loginsystem():
    """Ask for login details. Return (username, plain_password).

    The password is hashed later, once the user's salt is read from the DB.
    """
    user = input("Enter username:  ")
    pswd = getpass("Password: ")         # hidden while typing

    login = (user, pswd)

    return login

def main():
    """Connect to MySQL and run the register / login menu once."""

    connection = mysql.connector.connect(
        host = "127.0.0.1",
        user = "root",
        password = serverpassword,
        database = "users"
    )

    cursor = connection.cursor()

    choice = input("Select an option, 1 for register, 2 for login, 3 for exit: ")

    if (choice == '1'):
        login = createAccount()
        username = login[0]
        pswd = login[1]

        # Columns: (id, username, password). id = 0 lets AUTO_INCREMENT pick
        # the next id. %s placeholders keep the values safe from SQL injection.
        sql = ("insert into user values(%s, %s, %s)")
        values = (0, username, pswd)

        try:
            cursor.execute(sql, values)
            connection.commit()
            print("Account created!")
        except mysql.connector.IntegrityError:
            # Raised when the username column is UNIQUE and the name is taken
            print("That username is already taken.")

    elif (choice == '2'):
        login = loginsystem()
        username = login[0]
        pswd = login[1]

        # Look up the stored "salt$hash" for this username. The username is passed
        # as a parameter, not glued into the SQL string, to block SQL injection.
        sql = ("select password from user where username = %s")

        cursor.execute(sql, (username,))
        data = cursor.fetchone()          # None if no such user

        # Hash what the user typed with the stored salt, then compare.
        # compare_digest takes the same time either way, so timing can't leak the hash.
        if data is not None and "$" in data[0]:
            savedpass = data[0]
            salt = savedpass.split("$")[0]
            match = hmac.compare_digest(savedpass, hash_function(pswd, salt))
        else:
            match = False

        if match:
            print("Login successful! Welcome " + username)
        else:
            print("Login failed. Username/Password incorrect.")

    elif (choice == '3'):
        print("Goodbye.")

    # Always clean up the database connection
    cursor.close()
    connection.close()

if __name__ == "__main__":
    main()
