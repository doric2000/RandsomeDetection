import os
from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def encrypt_file(file_path, fernet):
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(file_path, "wb") as file:
        file.write(encrypted)

def decrypt_file(file_path, fernet):
    with open(file_path, "rb") as file:
        data = file.read()
    decrypted = fernet.decrypt(data)
    with open(file_path, "wb") as file:
        file.write(decrypted)

def process_directory(directory, fernet, mode):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if mode == "encrypt":
                    encrypt_file(file_path, fernet)
                    print(f"Encrypted: {file_path}")
                elif mode == "decrypt":
                    decrypt_file(file_path, fernet)
                    print(f"Decrypted: {file_path}")
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt all files in a directory.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("directory", help="Target directory")
    args = parser.parse_args()

    if args.mode == "encrypt":
        generate_key()
        key = load_key()
    else:
        if not os.path.exists("key.key"):
            print("Key file not found.")
            exit()
        key = load_key()

    fernet = Fernet(key)
    process_directory(args.directory, fernet, args.mode)