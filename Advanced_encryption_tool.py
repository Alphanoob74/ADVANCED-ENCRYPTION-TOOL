import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# Constants
BACKEND = default_backend()
BLOCK_SIZE = 128
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
ITERATIONS = 100_000

# Derives a key from a password using PBKDF2HMAC
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

# Encrypts a file using AES-256 in CBC mode
def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_data = salt + iv + ciphertext
    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_data)

# Decrypts a file encrypted by this tool
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE + 16]
    ciphertext = encrypted_data[SALT_SIZE + 16:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    output_path = file_path.replace(".enc", ".dec")
    with open(output_path, 'wb') as f:
        f.write(plaintext)

# GUI implementation using tkinter
def run_gui():
    def browse_encrypt():
        file_path = filedialog.askopenfilename()
        if file_path:
            password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
            if password:
                try:
                    encrypt_file(file_path, password)
                    messagebox.showinfo("Success", f"Encrypted file saved as {file_path}.enc")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def browse_decrypt():
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
            if password:
                try:
                    decrypt_file(file_path, password)
                    messagebox.showinfo("Success", f"Decrypted file saved as {file_path}.dec")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    window = tk.Tk()
    window.title("AES-256 File Encryption Tool")
    window.geometry("400x200")

    tk.Label(window, text="AES-256 Encryption Tool", font=("Arial", 16)).pack(pady=10)
    tk.Button(window, text="Encrypt File", command=browse_encrypt, width=25).pack(pady=10)
    tk.Button(window, text="Decrypt File", command=browse_decrypt, width=25).pack(pady=10)

    window.mainloop()

if __name__ == '__main__':
    run_gui()
