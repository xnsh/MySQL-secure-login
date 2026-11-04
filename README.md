# MySQL Login & Registration System (Salted PBKDF2-SHA256)

A command-line login and registration system in Python, backed by MySQL. Passwords are never stored as plain text. Each one is hashed with PBKDF2-HMAC-SHA256 and a random salt, and logins are checked by comparing hashes.

The MySQL password lives in a separate file (`secure.txt`) that is kept out of Git, so the code can be shared publicly without leaking credentials.

## Features

- **Register:** create a new account. The password is hashed before it is stored.
- **Login:** the typed password is hashed with the stored salt and checked against the stored hash.
- **Salted, slow hashing:** PBKDF2-HMAC-SHA256 with 600,000 rounds and a random 16-byte salt per user, using only the Python standard library.
- **Hidden password input:** passwords are read with `getpass`, so they don't show on screen.
- **Constant-time compare:** hashes are checked with `hmac.compare_digest`, so timing doesn't leak anything.
- **Separate credentials file:** the database password is read from `secure.txt`, not hard-coded.
- **SQL injection safe:** every query uses parameterized `%s` placeholders.
- **Duplicate check:** registering a username that is already taken shows a clear message.

## How It Works

```
 Register                                  Login
 --------                                  -----
 username, password                        username, password
        │                                         │
 salt = 16 random bytes                    SELECT password WHERE username = ?
 hash = PBKDF2(password, salt)                    │
        │                                  split stored "salt$hash"
 INSERT (id, username, "salt$hash")        hash = PBKDF2(password, salt)
        │                                         │
     MySQL  ◀─────────── user table ───────────▶ stored == "salt$hash" ?
                                                  │
                                       yes: "Login successful!"
                                       no:  "Login failed."
```

The same password and salt always give the same hash, and the hash can't be reversed. So the program can check a password without ever saving it.

- The **salt** makes every user's hash different, even when two people pick the same password. That breaks precomputed rainbow tables.
- **600,000 rounds** make each guess slow, so brute-force attacks take far longer.

The `password` column stores `salt$hash` as hex: 32 chars of salt, then `$`, then 64 chars of hash, for 97 chars total.

## Requirements

- Python 3.8+
- MySQL Server
- [`mysql-connector-python`](https://pypi.org/project/mysql-connector-python/)

```bash
pip install mysql-connector-python
```

## Setup

### 1. Create the database and table

Log in to MySQL and run:

```sql
CREATE DATABASE users;
USE users;

CREATE TABLE user (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL  -- "salt$hash" (97 chars)
);
```

Already made the table with `CHAR(64)`? Widen it, and delete any old accounts, since their unsalted hashes won't work anymore:

```sql
ALTER TABLE user MODIFY password VARCHAR(100) NOT NULL;
DELETE FROM user;
```

The column order must be `id, username, password`. The program inserts `0` for `id`, and MySQL's `AUTO_INCREMENT` fills in the real value.

### 2. Create `secure.txt`

In the same folder as `loginhashing.py`, make a file named `secure.txt` with only your MySQL root password on one line:

```
your_mysql_password
```

`secure.txt` is listed in `.gitignore`, so it won't be committed. **Never push this file.**

## Usage

```bash
python loginhashing.py
```

```
Select an option, 1 for register, 2 for login, 3 for exit: 1
Enter desired username:  bob
Set password:
Account created!
```

```
Select an option, 1 for register, 2 for login, 3 for exit: 2
Enter username:  bob
Password:
Login successful! Welcome bob
```

The program runs one action and then exits.

## Project Structure

```
.
├── loginhashing.py   # Register / login logic and MySQL queries
├── secure.txt        # MySQL password (you create this, git-ignored)
├── .gitignore
└── README.md
```

## Known Limitations

This is a learning project and is not meant for production:

- **PBKDF2, not Argon2:** PBKDF2 is solid and built into Python, but memory-hard hashes like Argon2 or bcrypt hold up better against GPU cracking.
- **Connects as `root`:** a real app should use a MySQL user with only the rights it needs.
- **No password rules:** empty or weak passwords are allowed.
- **Plain-text credentials file:** `secure.txt` is better than hard-coding, but environment variables or a secrets manager are safer.
- **One action per run:** the menu does not loop.

## Possible Improvements

- Switch to `argon2-cffi` or `bcrypt`
- Connect with a limited MySQL user instead of `root`
- Load credentials from environment variables
- Loop the menu until the user picks exit
- Add password strength rules

## Author

[**xnsh**](https://github.com/xnsh)
