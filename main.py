import os
import pymongo
import pyotp
import b64
import secrets
from getpass import getpass
from password_checker import check_password_strength  # Import the correct function
import aes
from Crypto.Util.Padding import pad, unpad

# MongoDB Connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["password_manager"]
users_collection = db["users"]

aes_block_size = 16  

# Self-implemented PBKDF2 function
def pbkdf2(password, salt, iterations=100000, key_len=32):
    password_bytes = password.encode("utf-8")
    key = bytearray(salt)
    
    for _ in range(iterations):
        new_key = bytearray(key_len)
        for i in range(key_len):
            new_key[i] = (password_bytes[i % len(password_bytes)] ^ key[i % len(key)]) & 0xFF
        key = new_key
    
    return bytes(key)  # Return raw bytes

# aes Encryption
def encrypt_aes(plaintext, key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = aes.new(key, aes.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), aes.block_size))
    return b64.b64encode(iv + ciphertext).decode()

# aes Decryption
def decrypt_aes(encrypted, key):
    encrypted_bytes = b64.b64decode(encrypted)
    iv = encrypted_bytes[:16]  # Extract IV
    ciphertext = encrypted_bytes[16:]  # Extract ciphertext
    cipher = aes.new(key, aes.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), aes.block_size)
    return decrypted.decode()

# User Registration
# Modify register_user() to encrypt OTP secret before storing it
def register_user():
    username = input("Enter username: ").strip()
    
    if users_collection.find_one({"username": username}):
        print("\u274c Username already exists. Choose another.")
        return
    
    while True:
        password = getpass("Enter password: ").strip()
        is_valid, message = check_password_strength(username, password)
        
        if is_valid:
            break
        else:
            print(f"\u274c Weak password: {message}")
    
    # Generate a random salt (16 bytes)
    salt = secrets.token_bytes(16)
    
    # Hash password using self-implemented PBKDF2
    key = pbkdf2(password, salt)
    encrypted_password = encrypt_aes(password, key)
    
    # Generate OTP secret
    otp_secret = pyotp.random_base32()

    # Encrypt OTP secret using AES
    encrypted_otp = encrypt_aes(otp_secret, key)

    # Store user data in MongoDB
    users_collection.insert_one({
        "username": username,
        "password": encrypted_password,
        "salt": b64.b64encode(salt).decode("utf-8"),
        "otp_secret": encrypted_otp  # Store encrypted OTP
    })
    
    print("✅ User registered successfully!")
    print(f"\U0001F511 Save this OTP secret for login: {otp_secret}")  # Show the actual OTP to the user

# Modify login_user() to decrypt OTP secret when verifying OTP
def login_user():
    username = input("Enter username: ").strip()
    user = users_collection.find_one({"username": username})
    
    if not user:
        print("\u274c Username does not exist.")
        return
    
    password = getpass("Enter password: ").strip()
    
    # Rehash the password entered by the user and compare with stored hash
    salt = b64.b64decode(user["salt"])
    key = pbkdf2(password, salt)
    
    try:
        decrypted_password = decrypt_aes(user["password"], key)
    except:
        print("\u274c Incorrect password.")
        return
    
    if password != decrypted_password:
        print("\u274c Incorrect password.")
        return
    
    # Decrypt the stored OTP secret before using it
    try:
        decrypted_otp = decrypt_aes(user["otp_secret"], key)
    except:
        print("\u274c OTP decryption failed. Possible data corruption.")
        return

    # Generate TOTP object with correct interval (DO NOT change to 300)
    totp = pyotp.TOTP(decrypted_otp)

    # Verify OTP with a slight time drift allowance
    otp = input("Enter OTP: ").strip()
    if totp.verify(otp, valid_window=2):  # Allows OTPs from last 2 intervals (~1 min tolerance)
        print("\U0001F514 Login successful!")
    else:
        print("\u274c Invalid OTP or OTP has expired. Please try again.")


# Main Menu
def main_menu():
    print("Welcome to the Password Manager!")
    print("1) Register a new user")
    print("2) Login")
    
    choice = input("Choose an option: ").strip()
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_user()
    else:
        print(" Invalid option. Exiting.")
        exit()

# Run the application
if __name__ == "__main__":
    main_menu()
