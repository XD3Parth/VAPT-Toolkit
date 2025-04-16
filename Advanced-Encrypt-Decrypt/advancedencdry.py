from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import binascii

# Function to generate a random key (AES 256)
def generate_key():
    return get_random_bytes(32)  # AES-256 requires a 32-byte key

# Function to encrypt data using AES
def encrypt_data(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    # Encode to base64 to make it human-readable
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
    print(f"Encrypted data saved to {file_name}")

# Function to load encrypted data from a file
def load_encrypted_file(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
        iv = lines[0].strip().split(": ")[1]
        cipher_text_b64 = lines[1].strip().split(": ")[1]
    return iv, cipher_text_b64

# Main function
def main():
    print("Welcome to the Advanced Encryption/Decryption Tool!")
    
    # Option for encryption or decryption
    operation = input("Would you like to (E)ncrypt or (D)ecrypt or (F)ile Operation? ").lower()

    if operation == 'e':
        plain_text = input("Enter the text to encrypt: ")
        key_input = input("Enter a 32-byte encryption key (leave blank for auto-generation): ")

        # Generate a random key if the user doesn't provide one
        if key_input == "":
            key = generate_key()
            print("Generated key:", binascii.hexlify(key).decode())
        else:
            key = bytes.fromhex(key_input)  # Convert hex input to bytes
        
        iv, cipher_text_b64 = encrypt_data(plain_text, key)
        print(f"Encrypted text (Base64 encoded): {cipher_text_b64}")
        print(f"IV (Base64 encoded): {iv}")
        
        # Save to file
        save_choice = input("Would you like to save the encrypted data to a file? (y/n): ").lower()
        if save_choice == 'y':
            file_name = input("Enter the filename (e.g., encrypted.txt): ")
            save_encrypted_file(file_name, iv, cipher_text_b64)
    
    elif operation == 'd':
        # Decrypting
        cipher_text_b64 = input("Enter the encrypted text (Base64 encoded): ")
        iv_b64 = input("Enter the IV (Base64 encoded): ")
        key_input = input("Enter the 32-byte key (in hexadecimal): ")
        key = bytes.fromhex(key_input)
        
        try:
            plain_text = decrypt_data(cipher_text_b64, key, iv_b64)
            print(f"Decrypted text: {plain_text}")
        except Exception as e:
            print(f"Error during decryption: {e}")
    
    elif operation == 'f':
        # File operation (Encrypt/Decrypt file)
        file_operation = input("Would you like to (E)ncrypt or (D)ecrypt a file? ").lower()
        
        if file_operation == 'e':
            file_path = input("Enter the file path to encrypt: ")
            with open(file_path, 'r') as file:
                plain_text = file.read()
            
            key_input = input("Enter a 32-byte encryption key (leave blank for auto-generation): ")
            if key_input == "":
                key = generate_key()
                print("Generated key:", binascii.hexlify(key).decode())
            else:
                key = bytes.fromhex(key_input)
            
            iv, cipher_text_b64 = encrypt_data(plain_text, key)
            print(f"Encrypted data:\nCipher Text (Base64): {cipher_text_b64}")
            print(f"IV (Base64): {iv}")
            
            # Save to file
            save_choice = input("Would you like to save the encrypted data to a file? (y/n): ").lower()
            if save_choice == 'y':
                file_name = input("Enter the filename (e.g., encrypted.txt): ")
                save_encrypted_file(file_name, iv, cipher_text_b64)
        
        elif file_operation == 'd':
            file_path = input("Enter the file path to decrypt: ")
            iv, cipher_text_b64 = load_encrypted_file(file_path)
            key_input = input("Enter the 32-byte key (in hexadecimal): ")
            key = bytes.fromhex(key_input)
            
            try:
                plain_text = decrypt_data(cipher_text_b64, key, iv)
                print(f"Decrypted file content:\n{plain_text}")
            except Exception as e:
                print(f"Error during decryption: {e}")

if __name__ == "__main__":
    main()
