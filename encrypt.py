#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

def generate_key():
    """Generate a key for encryption/decryption and save it to a file."""
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the encryption/decryption key from the file."""
    return open("key.key", "rb").read()

def encrypt_folder(folder_path):
    """Encrypt all files in the specified folder, set permissions to 000 for most files, and encrypt permissions.txt without changing its permissions."""
    # Generate and save a key if it doesn't exist
    if not os.path.exists("key.key"):
        key = generate_key()
    else:
        key = load_key()
    
    fernet = Fernet(key)
    
    # Dictionary to store original permissions
    original_permissions = {}
    
    # Iterate through all files in the folder
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        # Skip the key file and directories
        if file_path.endswith("key.key") or os.path.isdir(file_path):
            continue
        
        # Store the original permissions
        try:
            original_mode = os.stat(file_path).st_mode & 0o777
            original_permissions[file_path] = original_mode
        except Exception as e:
            print(f"Error accessing permissions of {file_path}: {e}")
            continue
        
        # Read the original file
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # Encrypt the data
        encrypted_data = fernet.encrypt(file_data)
        
        # Write the encrypted data back to the file
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        
        # Change the file permissions to --------- (no access for anyone), except for permissions.txt
        try:
            os.chmod(file_path, 0o000)  # Set permissions to 000 (---------)
            print(f"Changed permissions of {file_path} to ---------")
        except Exception as e:
            print(f"Error changing permissions of {file_path}: {e}")
    
    # Save original permissions to a file in the same directory
    permissions_file = os.path.join(folder_path, "permissions.txt")
    try:
        with open(permissions_file, "w") as perm_file:
            for file_path, mode in original_permissions.items():
                perm_file.write(f"{file_path}:{mode}\n")
        print(f"Saved permissions to {permissions_file}")
    except Exception as e:
        raise Exception(f"Could not save permissions to {permissions_file}: {e}")
    
    # Encrypt permissions.txt without changing its permissions
    try:
        # Store the original permissions of permissions.txt
        perm_file_mode = os.stat(permissions_file).st_mode & 0o777
        
        # Read the permissions.txt file
        with open(permissions_file, "rb") as perm_file:
            perm_data = perm_file.read()
        
        # Encrypt the data
        encrypted_perm_data = fernet.encrypt(perm_data)
        
        # Write the encrypted data back to permissions.txt
        with open(permissions_file, "wb") as perm_file:
            perm_file.write(encrypted_perm_data)
        
        # Restore the original permissions of permissions.txt
        os.chmod(permissions_file, perm_file_mode)
        print(f"Encrypted {permissions_file} and preserved its permissions")
    except Exception as e:
        raise Exception(f"Could not encrypt {permissions_file}: {e}")
    
    # Show pop-up notification
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Encryption Complete", f"The folder at {folder_path} has been encrypted.")
    root.destroy()

def decrypt_folder(folder_path):
    """Decrypt all files in the specified folder, including permissions.txt, and restore original permissions."""
    # Load the key
    if not os.path.exists("key.key"):
        raise FileNotFoundError("Key file not found. Cannot decrypt without the key.")
    
    key = load_key()
    fernet = Fernet(key)
    
    # First, decrypt permissions.txt to get the original permissions
    permissions_file = os.path.join(folder_path, "permissions.txt")
    original_permissions = {}
    if os.path.exists(permissions_file):
        try:
            # Temporarily set permissions to read the file
            os.chmod(permissions_file, 0o600)
            
            # Read the encrypted permissions.txt
            with open(permissions_file, "rb") as perm_file:
                encrypted_perm_data = perm_file.read()
            
            # Decrypt the data
            decrypted_perm_data = fernet.decrypt(encrypted_perm_data)
            
            # Write the decrypted data back temporarily to parse it
            with open(permissions_file, "wb") as perm_file:
                perm_file.write(decrypted_perm_data)
            
            # Parse the decrypted permissions
            with open(permissions_file, "r") as perm_file:
                for line in perm_file:
                    file_path, mode = line.strip().split(":")
                    original_permissions[file_path] = int(mode, 8)
            
            # Re-encrypt permissions.txt to maintain its encrypted state
            with open(permissions_file, "wb") as perm_file:
                perm_file.write(encrypted_perm_data)
            
            # Restore permissions of permissions.txt (likely unchanged, but ensure consistency)
            os.chmod(permissions_file, 0o644)  # Default permissions for permissions.txt
        except Exception as e:
            print(f"Warning: Could not decrypt {permissions_file}: {e}. Will use default permissions after decryption.")
    else:
        print(f"Warning: {permissions_file} not found. Will use default permissions after decryption.")
    
    # Iterate through all files in the folder
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        # Skip the key file and directories
        if file_path.endswith("key.key") or os.path.isdir(file_path):
            continue
        
        # Restore permissions temporarily to read the file
        try:
            os.chmod(file_path, 0o600)  # Temporarily set to rw------- so we can read the file
        except Exception as e:
            print(f"Error setting temporary permissions for {file_path}: {e}")
            continue
        
        # Read the encrypted file
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write the decrypted data back to the file
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        
        # Restore the original permissions
        if file_path in original_permissions:
            try:
                os.chmod(file_path, original_permissions[file_path])
                print(f"Restored permissions of {file_path} to {oct(original_permissions[file_path])}")
            except Exception as e:
                print(f"Error restoring permissions of {file_path}: {e}")
        else:
            # Fallback to default permissions if original not found
            try:
                os.chmod(file_path, 0o644)
                print(f"Restored permissions of {file_path} to rw-r--r-- (default)")
            except Exception as e:
                print(f"Error setting default permissions of {file_path}: {e}")

def main():
    # Specify the folder path to encrypt/decrypt
    folder_path = input("Enter the folder path to encrypt/decrypt: ")
    
    if not os.path.isdir(folder_path):
        print("Invalid folder path.")
        return
    
    action = input("Enter 'encrypt' to encrypt or 'decrypt' to decrypt: ").lower()
    
    try:
        if action == "encrypt":
            encrypt_folder(folder_path)
            print("Encryption completed.")
        elif action == "decrypt":
            decrypt_folder(folder_path)
            print("Decryption completed.")
        else:
            print("Invalid action. Please enter 'encrypt' or 'decrypt'.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
	main()
