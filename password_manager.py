import sqlite3
import string
import secrets
import os
import stat
import getpass
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = "master.salt"
PERMS = stat.S_IRUSR | stat.S_IWUSR

def chmod(path: str):
    try:
        os.chmod(path, PERMS)
    except Exception:
        pass

def derive_key(pwd: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return urlsafe_b64encode(kdf.derive(pwd))

def get_fernet_key() -> bytes:
    TEST_MESSAGE = b"VALIDATION_TEST"
    if not os.path.exists(SALT_FILE):
        print("=== First-time setup ===")
        while True:
            p1 = getpass.getpass("Choose a strong master password: ")
            p2 = getpass.getpass("Confirm master password: ")
            if p1 and p1 == p2:
                break
            print("Mismatch, try again.")
        salt = os.urandom(16)
        key = derive_key(p1.encode(), salt)
        f = Fernet(key)
        token = f.encrypt(TEST_MESSAGE)
        with open(SALT_FILE, "wb") as f:
            f.write(salt + token)
        chmod(SALT_FILE)
        print("Master password created.")
        return key

    with open(SALT_FILE, "rb") as f:
        data = f.read()
        if len(data) < 16:
            raise SystemExit("Corrupted master.salt file.")
        salt = data[:16]
        stored_token = data[16:]

    for attempt in range(1, 4):
        pwd = getpass.getpass(f"Master password (attempt {attempt}/3): ")
        candidate = derive_key(pwd.encode(), salt)
        try:
            f = Fernet(candidate)
            if f.decrypt(stored_token) == TEST_MESSAGE:
                return candidate
        except InvalidToken:
            pass
        print("Incorrect Password")
    raise SystemExit("Too many failed attempts.")

class PasswordManager:
    def __init__(self, db_file: str = "passwords.db"):
        self.db_file = db_file
        self.cipher = Fernet(get_fernet_key())
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL
                )
                """
            )
            con.commit()

    def encrypt(self, plaintext: str) -> str:
        return self.cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self.cipher.decrypt(token.encode()).decode()
        except InvalidToken:
            raise ValueError("Wrong master password or corrupted data")

    def generate_password(self, length: int = 16) -> str:
        if length < 8:
            length = 8
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def add(self, account: str, username: str, password: str | None = None):
        if not account or not username:
            raise ValueError("Account and username are required.")
        if password is None:
            password = self.generate_password()
            print(f"Generated password: {password}")

        enc = self.encrypt(password)
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO passwords (account, username, encrypted_password) "
                "VALUES (?, ?, ?)",
                (account, username, enc),
            )
            con.commit()
        print(f"Password for '{account}' saved.")

    def get(self, account: str) -> dict | None:
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute(
                "SELECT username, encrypted_password FROM passwords WHERE account = ?",
                (account,),
            )
            row = cur.fetchone()
            if not row:
                return None
            username, enc = row
            pwd = self.decrypt(enc)
            return {"account": account, "username": username, "password": pwd}

    def list_accounts(self) -> list[str]:
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute("SELECT account FROM passwords")
            return [r[0] for r in cur.fetchall()]

    def delete(self, account: str):
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute("SELECT 1 FROM passwords WHERE account = ?", (account,))
            if not cur.fetchone():
                print(f"No entry for '{account}'.")
                return
            cur.execute("DELETE FROM passwords WHERE account = ?", (account,))
            con.commit()
            print(f"Deleted '{account}'.")

    def update(self, account: str, new_password: str | None = None):
        if new_password is None:
            new_password = self.generate_password()
            print(f"Generated new password: {new_password}")

        enc = self.encrypt(new_password)
        with sqlite3.connect(self.db_file) as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE passwords SET encrypted_password = ? WHERE account = ?",
                (enc, account),
            )
            if cur.rowcount == 0:
                print(f"No entry for '{account}'.")
                return
            con.commit()
            print(f"Password for '{account}' updated.")

def main():
    pm = PasswordManager()

    while True:
        print("\n=== Password Manager ===")
        print("1. Generate a new password")
        print("2. Add / overwrite a password")
        print("3. Retrieve a password")
        print("4. List all accounts")
        print("5. Delete an account")
        print("6. Update a password")
        print("7. Exit")
        choice = input("Choose (1-7): ").strip()

        try:
            if choice == "1":
                length = input("Length [16]: ").strip()
                length = int(length) if length.isdigit() else 16
                print(f"Password: {pm.generate_password(length)}")

            elif choice == "2":
                account = input("Account (e.g., Gmail): ").strip()
                username = input("Username: ").strip()
                pwd = input("Password (Enter to generate): ").strip()
                pm.add(account, username, pwd or None)

            elif choice == "3":
                acct = input("Account: ").strip()
                data = pm.get(acct)
                if data:
                    print(f"Account : {data['account']}")
                    print(f"Username: {data['username']}")
                    print(f"Password: {data['password']}")
                else:
                    print("Not found.")

            elif choice == "4":
                accounts = pm.list_accounts()
                if accounts:
                    print("Stored accounts:")
                    for a in accounts:
                        print(f"  * {a}")
                else:
                    print("No accounts yet.")

            elif choice == "5":
                acct = input("Account to delete: ").strip()
                pm.delete(acct)

            elif choice == "6":
                acct = input("Account to update: ").strip()
                pwd = input("New password (Enter to generate): ").strip()
                pm.update(acct, pwd or None)

            elif choice == "7":
                print("Good-bye!")
                break

            else:
                print("Invalid option.")

        except (ValueError, RuntimeError) as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            print("\nAborted.")
            break

if __name__ == "__main__":
    main()