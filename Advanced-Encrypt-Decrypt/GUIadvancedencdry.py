from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import binascii
import tkinter as tk
from tkinter import messagebox, filedialog

# Function to generate a random key (AES 256)
def generate_key():
    return get_random_bytes(32)  # AES-256 requires a 32-byte key

# Function to encrypt data using AES
def encrypt_data(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    cipher_text_b64 = base64.b64encode(cipher_text).decode('utf-8')
    return iv, cipher_text_b64

# Function to decrypt data using AES
def decrypt_data(cipher_text_b64, key, iv_b64):
    iv = base64.b64decode(iv_b64)
    cipher_text = base64.b64decode(cipher_text_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')
    return plain_text

# Function to save encrypted data to a file
def save_encrypted_file(file_name, iv, cipher_text_b64):
    with open(file_name, 'w') as file:
        file.write(f"IV: {iv}\n")
        file.write(f"Cipher Text: {cipher_text_b64}\n")
    messagebox.showinfo("Save File", f"Encrypted data saved to {file_name}")

# Function to load encrypted data from a file
def load_encrypted_file(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
        iv = lines[0].strip().split(": ")[1]
        cipher_text_b64 = lines[1].strip().split(": ")[1]
    return iv, cipher_text_b64

# Function to import a key from a file
def import_key():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            key_hex = file.read().strip()
            key_entry.delete(0, tk.END)
            key_entry.insert(tk.END, key_hex)

# Function to export a key to a file
def export_key():
    key_hex = key_entry.get().strip()
    if len(key_hex) == 64:
        file_path = filedialog.asksaveasfilename(defaultextension=".key")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(key_hex)
            messagebox.showinfo("Export Key", f"Key saved to {file_path}")
    else:
        messagebox.showerror("Error", "Invalid key length. Ensure it is a 32-byte key in hexadecimal format.")

# GUI Functions
def encrypt_text():
    plain_text = text_entry.get("1.0", tk.END).strip()
    key_input = key_entry.get().strip()

    if not plain_text:
        messagebox.showerror("Error", "Please enter text to encrypt.")
        return

    if key_input == "":
        key = generate_key()
        key_entry.insert(0, binascii.hexlify(key).decode())
    else:
        key = bytes.fromhex(key_input)
    
    iv, cipher_text_b64 = encrypt_data(plain_text, key)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"IV: {iv}\nCipher Text: {cipher_text_b64}")

def decrypt_text():
    cipher_text = text_entry.get("1.0", tk.END).strip()
    iv_b64 = iv_entry.get().strip()
    key_input = key_entry.get().strip()

    if not cipher_text or not key_input or not iv_b64:
        messagebox.showerror("Error", "All fields (cipher text, key, and IV) must be provided for decryption.")
        return

    key = bytes.fromhex(key_input)

    try:
        plain_text = decrypt_data(cipher_text, key, iv_b64)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, plain_text)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def copy_to_clipboard():
    result = result_text.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(result)
    messagebox.showinfo("Copied", "Text copied to clipboard.")

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        iv, cipher_text_b64 = load_encrypted_file(file_path)
        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, cipher_text_b64)
        iv_entry.delete(0, tk.END)
        iv_entry.insert(tk.END, iv)

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        iv = iv_entry.get().strip()
        cipher_text_b64 = text_entry.get("1.0", tk.END).strip()
        save_encrypted_file(file_path, iv, cipher_text_b64)

# GUI Setup
root = tk.Tk()
root.title("Advanced AES Encryption/Decryption Tool")

# Text input
tk.Label(root, text="Enter text:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
text_entry = tk.Text(root, height=10, width=50)
text_entry.grid(row=0, column=1, padx=10, pady=5)

# Key input
tk.Label(root, text="Enter key (32-byte hex):").grid(row=1, column=0, padx=10, pady=5, sticky="e")
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=5)

# IV input
tk.Label(root, text="Enter IV (Base64):").grid(row=2, column=0, padx=10, pady=5, sticky="e")
iv_entry = tk.Entry(root, width=50)
iv_entry.grid(row=2, column=1, padx=10, pady=5)

# Buttons
tk.Button(root, text="Encrypt", command=encrypt_text).grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="Decrypt", command=decrypt_text).grid(row=3, column=1, padx=10, pady=5, sticky="w")
tk.Button(root, text="Open File", command=open_file).grid(row=4, column=0, padx=10, pady=5)
tk.Button(root, text="Save File", command=save_file).grid(row=4, column=1, padx=10, pady=5, sticky="w")
tk.Button(root, text="Import Key", command=import_key).grid(row=5, column=0, padx=10, pady=5)
tk.Button(root, text="Export Key", command=export_key).grid(row=5, column=1, padx=10, pady=5, sticky="w")

# Result text
tk.Label(root, text="Result:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
result_text = tk.Text(root, height=10, width=50)
result_text.grid(row=6, column=1, padx=10, pady=5)

tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=7, columnspan=2, padx=10, pady=5)

# Run the GUI event loop
root.mainloop()
