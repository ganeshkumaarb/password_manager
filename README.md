# VaultKey — Password Manager

A simple local password manager built with Python, Flask, and SQLite.

## Requirements

- Python 3.8+
- Flask
- cryptography

## Install & Run

```bash
pip install flask cryptography
python app.py
```

Open http://localhost:5000 in your browser.

## First Time Setup

1. Create a master password (minimum 8 characters)
2. This password **cannot be recovered** if lost — store it somewhere safe
3. All your passwords are encrypted using this master password

## Features

- Add, edit, delete passwords
- Search by site or username
- Show/hide passwords on demand
- Copy passwords to clipboard
- Generate random passwords
- All data stored locally in `passwords.db`

## Security

- Master password hashed with PBKDF2-SHA256
- Stored passwords encrypted with AES-256 (Fernet)
- Nothing leaves your machine

## File Structure

```
├── app.py                  # Main application
├── passwords.db            # SQLite database (auto-created)
└── templates/
    ├── setup.html          # Master password creation
    ├── unlock.html         # Login
    ├── vault.html          # Password list
    └── form.html           # Add / edit form
```
