– Password Manager

# Secure Password Manager

A **cryptographically secure**, local password manager built with Python and `cryptography`.

**No plaintext. No weak links.**

---

## Features

- Master Password → PBKDF2 (600,000 iterations) → Fernet (AES-128)
- **Salt + Validation Token** → instant wrong-password detection
- Secure Password Generation (`secrets`)
- Add, Retrieve, Update, Delete passwords
- **File permissions locked** (`600`)
- SQLite backend (lightweight, local)

---

## Security Model

| Threat | Protection |
|-------|------------|
| Brute-force | 600k PBKDF2 + 3 attempts |
| Wrong password | Validation token fails fast |
| File tampering | `InvalidToken` on decrypt |
| OS access | `chmod 600` on `master.salt` |
| Shoulder surfing | `getpass.getpass()` |

> **Tamper-proof. Audit-ready.**

---

## Project Structure
.
├── password_manager.py     # Full app
├── master.salt             # Salt + encrypted token (auto-created)
├── passwords.db            # Encrypted passwords (auto-created)
└── README.md
text---

## Setup & Run

### 1. Install

pip install cryptography
2. Run
bashpython password_manager.py
First Run:
text=== First-time setup ===
Choose a strong master password: ********
Confirm master password: ********
Master password created.

Usage
text=== Password Manager ===
1. Generate a new password
2. Add / overwrite a password
3. Retrieve a password
4. List all accounts
5. Delete an account
6. Update a password
7. Exit

Example
textChoose (1-7): 2
Account (e.g., Gmail): Gmail
Username: john.doe@gmail.com
Password (Enter to generate): [Enter]
Generated password: k8@L2mP9!xY3vN5

Choose (1-7): 3
Account: Gmail
Account : Gmail
Username: john.doe@gmail.com
Password: k8@L2mP9!xY3vN5
