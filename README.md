## ADVANCED-ENCRYPTION-TOOL  ## 

COMPANY : CODTECH IT SOLUTIONS

NAME : SUDHANSHU NIGAM

INTERN ID : CT06DF444

DOMAIN : CYBER SECURITY & ETHICAL HACKING

DURATIONS : 6 WEEK

MENTOR : NEELA SANTOSH

##  DESCRIPTION  ##

🔐 Advanced AES-256 File Encryption Tool (GUI Powered)

Protect what matters. Encrypt with confidence.
This Python-based desktop application allows you to securely encrypt and decrypt files using military-grade AES-256 encryption—all wrapped in a simple and intuitive Tkinter GUI. Whether you're a privacy enthusiast or a cybersecurity student, this tool keeps your sensitive data safe and easy to handle.

🧰 Key Features

    🔐 AES-256 Encryption: Uses CBC mode with PKCS7 padding for strong symmetric encryption.

    🧬 Secure Key Derivation: Implements PBKDF2HMAC with SHA-256 and salting to protect passwords.

    🧠 Automatic Salt & IV Handling: Randomly generates salt and IV for each encryption session.

    💻 User-Friendly Interface: Clean, minimal GUI built with tkinter—no command-line needed.

    📁 File-Based Workflow: Encrypt and decrypt any file on your system with just a few clicks.

🛠️ Built With
Library	                         Purpose
cryptography	                   AES encryption, key derivation, padding
tkinter	                         Desktop GUI interface
base64	                         For safe encoding/decoding if needed
os	                             Secure random salt/IV generation

🚀 How to Use

   Install dependencies:
           
        pip install cryptography

   Run the script:

        python Advanced_encryption_tool.py

   In the GUI:

    🔒 Click "Encrypt File" → Choose a file → Set a password → Encrypted .enc file is saved.

    🔓 Click "Decrypt File" → Choose a .enc file → Enter the correct password → Decrypted .dec file is saved.

📂 File Output Format

    file.txt → encrypted → file.txt.enc

    file.txt.enc → decrypted → file.txt.dec

⚠️ Security Disclaimer

This tool is intended for educational and secure local use only.
Do not share passwords, and always backup your original files.
Incorrect passwords will result in decryption failure or data loss.

###   OUTPUT   ###

![Image](https://github.com/user-attachments/assets/c71107a7-2f28-4759-9e26-31eca41a0eba)
