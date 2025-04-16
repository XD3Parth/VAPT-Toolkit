# 🔐 Encryption Tool

This is a simple encryption and decryption tool built using Python and Tkinter. The application allows users to generate encryption keys, encrypt messages, and decrypt them securely.

## ✨ Features
- 🔑 Generate a secure encryption key.
- 📂 Load and save encryption keys.
- 🔏 Encrypt and decrypt messages.
- 📄 Save and load encrypted messages from files.
- 📋 Copy encrypted/decrypted text to the clipboard.
- 📝 Log events for tracking actions.

## ⚡ Installation
Ensure you have Python installed. Then, install the required libraries:

```sh
pip install tk
```

## 🚀 Usage
Run the script using Python:

```sh
python henc.py
```

### 🔒 Encryption
1. 🔑 Generate a key or load an existing one.
2. 📝 Enter the message in the input field.
3. 🔏 Click the "Enc" button to encrypt the message.
4. 📋 Copy, save, or use the encrypted output.

### 🔓 Decryption
1. 📂 Load or enter the encrypted message.
2. 🔓 Click the "Dec" button to decrypt it using the correct key.
3. 👀 View the decrypted message in the output field.

## 📁 File Operations
- 💾 **Save Key:** Save the generated encryption key to a file.
- 📂 **Load Key:** Load an existing encryption key from a file.
- 💾 **Save Message:** Save an encrypted or decrypted message to a file.
- 📂 **Load Message:** Load a message from a file to encrypt or decrypt.

## ⚠️ Notes
- 🔄 The encryption process uses a random seed-based method, making it crucial to use the correct key for decryption.
- 📜 The application provides a log section for tracking encryption and decryption events.

## 📜 License
This project is open-source and free to use. 🎉

