import hashlib
import bcrypt
import hmac
from argon2 import PasswordHasher
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Argon2 password hasher
argon2_hasher = PasswordHasher()

# Define a pepper for added security
PEPPER = "my_secure_pepper"

def generate_hash(data, algorithm, salt=None, use_salt_pepper=True):
    if use_salt_pepper:
        if salt is None:
            salt = os.urandom(16).hex()
        salted_data = data + salt + PEPPER
    else:
        salted_data = data

    if algorithm == 'md5':
        hashed = hashlib.md5(salted_data.encode()).hexdigest()
    elif algorithm == 'sha1':
        hashed = hashlib.sha1(salted_data.encode()).hexdigest()
    elif algorithm == 'sha256':
        hashed = hashlib.sha256(salted_data.encode()).hexdigest()
    elif algorithm == 'sha512':
        hashed = hashlib.sha512(salted_data.encode()).hexdigest()
    elif algorithm == 'bcrypt':
        hashed = bcrypt.hashpw(salted_data.encode(), bcrypt.gensalt()).decode()
    elif algorithm == 'argon2':
        hashed = argon2_hasher.hash(salted_data)
    elif algorithm == 'hmac':
        key = os.urandom(32)
        hashed = hmac.new(key, salted_data.encode(), hashlib.sha256).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm.")

    return hashed, salt

def verify_hash(data, hashed, algorithm, salt=None, use_salt_pepper=True):
    try:
        if use_salt_pepper:
            salted_data = data + (salt or "") + PEPPER
        else:
            salted_data = data

        if algorithm in ['md5', 'sha1', 'sha256', 'sha512']:
            return generate_hash(data, algorithm, salt, use_salt_pepper)[0] == hashed
        elif algorithm == 'bcrypt':
            return bcrypt.checkpw(salted_data.encode(), hashed.encode())
        elif algorithm == 'argon2':
            return argon2_hasher.verify(hashed, salted_data)
        elif algorithm == 'hmac':
            key = os.urandom(32)  # Assuming a consistent key for HMAC verification
            return hmac.new(key, salted_data.encode(), hashlib.sha256).hexdigest() == hashed
        else:
            raise ValueError("Unsupported hashing algorithm.")
    except Exception as e:
        return False

def main():
    def on_generate():
        data = data_entry.get().strip()
        algorithm = algorithm_var.get().lower()
        use_salt_pepper = salt_pepper_var.get()

        if not data:
            messagebox.showwarning("Input Error", "Please enter some data to hash.")
            return

        try:
            hashed, salt = generate_hash(data, algorithm, use_salt_pepper=use_salt_pepper)
            result_var.set(f"Generated {algorithm.upper()} Hash:\n{hashed}\nSalt: {salt}")
            # Save the generated hash and salt for separate copying
            global generated_hash, generated_salt
            generated_hash = hashed
            generated_salt = salt
        except ValueError as ve:
            messagebox.showerror("Error", f"An error occurred: {ve}")

    def on_verify():
        data = data_entry.get().strip()
        hashed = hash_entry.get().strip()
        salt = salt_entry.get().strip()
        algorithm = algorithm_var.get().lower()
        use_salt_pepper = salt_pepper_var.get()

        if not data or not hashed:
            messagebox.showwarning("Input Error", "Please enter data and hash to verify.")
            return

        is_valid = verify_hash(data, hashed, algorithm, salt, use_salt_pepper)
        result_var.set(f"Verification Result: {'Valid' if is_valid else 'Invalid'}")

    def copy_hash_to_clipboard():
        if generated_hash:
            root.clipboard_clear()
            root.clipboard_append(generated_hash)
            root.update()
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("No Hash", "No hash to copy!")

    def copy_salt_to_clipboard():
        if generated_salt:
            root.clipboard_clear()
            root.clipboard_append(generated_salt)
            root.update()
            messagebox.showinfo("Copied", "Salt copied to clipboard!")
        else:
            messagebox.showwarning("No Salt", "No salt to copy!")

    def clear_fields():
        data_entry.delete(0, tk.END)
        hash_entry.delete(0, tk.END)
        salt_entry.delete(0, tk.END)
        result_var.set("")

    root = tk.Tk()
    root.title("Advanced Hash Generator and Verifier")
    root.geometry("600x450")
    root.resizable(False, False)

    # Create a main frame for better organization
    frame = ttk.Frame(root, padding="20")
    frame.grid(row=0, column=0)

    # Data entry section
    tk.Label(frame, text="Enter Data:", anchor="w").grid(row=0, column=0, pady=5, padx=10, sticky="w")
    data_entry = ttk.Entry(frame, font=("Arial", 12), width=40)
    data_entry.grid(row=0, column=1, pady=5, padx=10)

    # Hash entry section
    tk.Label(frame, text="Enter Hash (for verification):", anchor="w").grid(row=1, column=0, pady=5, padx=10, sticky="w")
    hash_entry = ttk.Entry(frame, font=("Arial", 12), width=40)
    hash_entry.grid(row=1, column=1, pady=5, padx=10)

    # Salt entry section
    tk.Label(frame, text="Enter Salt (if applicable):", anchor="w").grid(row=2, column=0, pady=5, padx=10, sticky="w")
    salt_entry = ttk.Entry(frame, font=("Arial", 12), width=40)
    salt_entry.grid(row=2, column=1, pady=5, padx=10)

    # Algorithm selection
    tk.Label(frame, text="Select Algorithm:", anchor="w").grid(row=3, column=0, pady=5, padx=10, sticky="w")
    algorithm_var = tk.StringVar(value="md5")
    algorithms = ["MD5", "SHA1", "SHA256", "SHA512", "Bcrypt", "Argon2", "HMAC"]
    algorithm_combo = ttk.Combobox(frame, values=algorithms, textvariable=algorithm_var, state="readonly")
    algorithm_combo.grid(row=3, column=1, pady=5, padx=10)

    # Salt and Pepper option
    salt_pepper_var = tk.BooleanVar(value=True)
    salt_pepper_checkbox = ttk.Checkbutton(frame, text="Use Salt and Pepper", variable=salt_pepper_var)
    salt_pepper_checkbox.grid(row=4, column=0, columnspan=2, pady=10)

    # Buttons section
    ttk.Button(frame, text="Generate Hash", command=on_generate).grid(row=5, column=0, pady=10, padx=10, sticky="ew")
    ttk.Button(frame, text="Verify Hash", command=on_verify).grid(row=5, column=1, pady=10, padx=10, sticky="ew")

    # Copy hash and salt buttons
    ttk.Button(frame, text="Copy Hash to Clipboard", command=copy_hash_to_clipboard).grid(row=6, column=0, pady=5, padx=10, sticky="ew")
    ttk.Button(frame, text="Copy Salt to Clipboard", command=copy_salt_to_clipboard).grid(row=6, column=1, pady=5, padx=10, sticky="ew")

    # Clear fields button
    ttk.Button(frame, text="Clear Fields", command=clear_fields).grid(row=7, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    # Result display
    result_var = tk.StringVar(value="")
    result_label = ttk.Label(frame, textvariable=result_var, anchor="w", justify="left", wraplength=500)
    result_label.grid(row=8, column=0, columnspan=2, pady=15, padx=10)

    root.mainloop()

if __name__ == "__main__":
    generated_hash = None
    generated_salt = None
    main()
