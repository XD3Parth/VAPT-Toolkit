# Hash Generator and Verifier

A Python-based tool for generating and verifying hashes using multiple algorithms, such as MD5, SHA1, SHA256, SHA512, Bcrypt, Argon2, and HMAC. It provides an easy-to-use graphical user interface (GUI) built with `tkinter`. This tool is useful for developers, security professionals, and anyone looking to securely hash passwords, data, or verify hash integrity.

## Features
- **Generate Hashes**: Supports multiple hashing algorithms including MD5, SHA1, SHA256, SHA512, Bcrypt, Argon2, and HMAC.
- **Hash Verification**: Verifies whether a provided hash matches the expected data.
- **Salt & Pepper Support**: Option to include custom salt and pepper for enhanced security.
- **Clipboard Copying**: Easy copying of generated hashes and salts directly to your clipboard.
- **Graphical User Interface (GUI)**: Simple and user-friendly interface using `tkinter`.

## Installation

1. Clone the repository or download the Python file.
2. Ensure that you have Python 3.x installed on your system.
3. Install the required dependencies:
   ```bash
   pip install bcrypt argon2-cffi
   ```

## Usage

### 1. Run the Application

Run the Python script to launch the GUI:

```bash
python hash_generator.py
```

### 2. Generate a Hash

- **Enter Data**: Type the data you want to hash.
- **Select Algorithm**: Choose one of the available algorithms (MD5, SHA1, SHA256, SHA512, Bcrypt, Argon2, HMAC).
- **Use Salt & Pepper**: Choose whether to include salt and pepper for enhanced security.
- **Click "Generate Hash"**: The hash and salt will be generated.

### 3. Verify a Hash

- **Enter Data and Hash**: Input the data and the hash to verify.
- **Enter Salt (if applicable)**: If you used salt while generating the hash, input it here.
- **Click "Verify Hash"**: The tool will check if the data matches the hash.

### 4. Copy to Clipboard

- Click on **"Copy Hash to Clipboard"** to copy the generated hash.
- Click on **"Copy Salt to Clipboard"** to copy the salt value.

### 5. Clear Fields

Click **"Clear Fields"** to reset all inputs and results.

## Supported Hashing Algorithms
- **MD5**: A widely used but insecure hashing algorithm.
- **SHA1**: Another widely used algorithm, but considered insecure.
- **SHA256**: A more secure version of SHA.
- **SHA512**: Offers even more security than SHA256.
- **Bcrypt**: A password hashing algorithm designed for security.
- **Argon2**: The latest and most secure password hashing algorithm.
- **HMAC (Hash-based Message Authentication Code)**: Used for verifying the integrity of data.

## Example

### Generate Hash

1. Enter some data (e.g., `my_password`).
2. Select `SHA256` as the algorithm.
3. Choose to use Salt & Pepper.
4. Click **Generate Hash**.
5. The generated hash and salt will be displayed.

### Verify Hash

1. Enter the original data (`my_password`) and the generated hash.
2. Enter the generated salt.
3. Click **Verify Hash** to check if the hash matches the data.

## Contributions

Feel free to contribute! Open issues, submit pull requests, and make suggestions to improve this tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
