---

# Advanced Encryption and Decryption Tool

A Python-based tool for securely encrypting and decrypting data using AES-256 encryption. This tool supports encryption and decryption of both text and files, providing strong security for sensitive information. The tool allows the user to choose between AES encryption with a custom key or automatic key generation, making it suitable for various use cases.

## Features

- **AES-256 Encryption**: Strong AES-256 encryption to protect your data.
- **Support for Text and File Encryption/Decryption**: Encrypt and decrypt both text and files.
- **Custom Key or Auto-Generated Key**: Allows users to provide a custom encryption key or automatically generate a random key.
- **Base64 Encoding**: Encodes encrypted data and initialization vectors in Base64 format for easy sharing and storage.
- **Password-based Key Generation**: Derives the encryption key from a password for secure key management.
- **File Handling**: Supports encrypting and decrypting entire files, making it ideal for secure file storage or transmission.
- **Secure Initialization Vector (IV)**: Uses a random IV for each encryption, enhancing security.

## Requirements

- Python 3.x
- PyCryptodome Library (for AES encryption)

## Installation

### Step 1: Install Python 3.x
Ensure Python 3.x is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

### Step 2: Install Dependencies

To install the required cryptography library `PyCryptodome`, run the following command:

```bash
pip install pycryptodome
```

## Usage

1. **Clone this repository**:
   Clone the repository to your local machine:

   ```bash
   git clone https://github.com/ParthXD7/Advanced-Encryption-Decryption-Tool.git
   cd Advanced-Encryption-Decryption-Tool
   ```

2. **Run the Tool**:
   After downloading the repository, you can run the tool with the following Python script:

   ```bash
   python encryption_tool.py
   ```

3. **Basic Usage**:
   The tool allows users to encrypt/decrypt messages or files. It supports encryption and decryption through a simple command-line interface.

### Example Use Cases

#### Encrypting a Message:
```plaintext
Enter the text to encrypt: Hello World!
Enter a 32-byte encryption key (leave blank for auto-generation): 
Generated key: d4f44fa7b5278b3f56a35088a03abf06e742e38ff8b2876da2905f321b8b3b7f

Encrypted text: 3fcf3c02a8e640aa71763194401b8e29
```

#### Decrypting a Message:
```plaintext
Enter the encrypted text: 3fcf3c02a8e640aa71763194401b8e29
Enter the 32-byte encryption key: d4f44fa7b5278b3f56a35088a03abf06e742e38ff8b2876da2905f321b8b3b7f
Decrypted text: Hello World!
```

#### Encrypting/Decrypting a File:

The tool also supports file encryption and decryption, which is especially useful for securely storing or transmitting files.

##### Encrypt a File:

```bash
python encryption_tool.py --encrypt --file "path_to_file.txt"
```

##### Decrypt a File:

```bash
python encryption_tool.py --decrypt --file "path_to_encrypted_file.txt"
```

## How it Works

1. **AES-256 Encryption**: The tool uses the AES algorithm with a 256-bit key for strong encryption. AES is one of the most widely used encryption algorithms and is considered highly secure for encrypting sensitive data.
   
2. **Key Generation**: If a key is not provided, the tool generates a random 32-byte key and uses it for encryption. Alternatively, you can provide a custom key.
   
3. **Base64 Encoding**: The encrypted text is encoded in Base64 to make it human-readable and easy to transmit or store. The initialization vector (IV) used for encryption is also encoded in Base64.

4. **File Encryption**: The tool can also encrypt and decrypt entire files, ensuring the confidentiality of stored data.

## Code Structure

- **`encrypt()`**: This function takes plaintext and the encryption key, and returns the encrypted data.
- **`decrypt()`**: This function takes the encrypted data and the key, and returns the original plaintext.
- **`generate_key()`**: This function generates a random 32-byte key if no key is provided by the user.
- **`file_operations()`**: This function handles file encryption and decryption, allowing users to process large files.
- **`main()`**: The main function interacts with the user, handling input and executing the appropriate encryption or decryption process.

## Command-Line Arguments

- `--encrypt`: Encrypt the provided text or file.
- `--decrypt`: Decrypt the provided encrypted text or file.
- `--file`: Specify the file to encrypt or decrypt.
- `--key`: Provide a custom 32-byte encryption key (optional, if not provided, a random key will be generated).
- `--password`: Use a password to derive the encryption key (optional).

## Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Create a new Pull Request

## License

This project is open-source and available under the [MIT License](LICENSE).

---
