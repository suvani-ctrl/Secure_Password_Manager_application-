import os
import pymongo
import pyotp
import base64
import secrets
from getpass import getpass
from password_checker import check_password_strength  # Import the correct function

# MongoDB Connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["password_manager"]
users_collection = db["users"]

# Self-implemented PBKDF2 function
def pbkdf2(password, salt, iterations=100000, key_len=32):
    password_bytes = password.encode("utf-8")
    key = bytearray(salt)
    
    for _ in range(iterations):
        new_key = bytearray(key_len)
        for i in range(key_len):
            new_key[i] = (password_bytes[i % len(password_bytes)] ^ key[i % len(key)]) & 0xFF
        key = new_key
    
    return base64.b64encode(bytes(key)).decode("utf-8")

# User Registration
def register_user():
    username = input("Enter username: ").strip()
    
    if users_collection.find_one({"username": username}):
        print("❌ Username already exists. Choose another.")
        return
    
    while True:
        password = getpass("Enter password: ").strip()
        is_valid, message = check_password_strength(username, password)
        
        if is_valid:
            break
        else:
            print(f"❌ Weak password: {message}")
    
    # Generate a random salt (16 bytes)
    salt = secrets.token_bytes(16)
    
    # Hash password using self-implemented PBKDF2
    hashed_password = pbkdf2(password, salt)
    
    # Generate OTP secret
    otp_secret = pyotp.random_base32()
    
    # Store user data in MongoDB
    users_collection.insert_one({
        "username": username,
        "password": hashed_password,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "otp_secret": otp_secret
    })
    
    print("\n✅ User registered successfully!")
    print(f"🔑 Save this OTP secret for login: {otp_secret}")

# User Login
# User Login
def login_user():
    username = input("Enter username: ").strip()
    user = users_collection.find_one({"username": username})
    
    if not user:
        print("❌ Username does not exist.")
        return
    
    password = getpass("Enter password: ").strip()
    
    # Rehash the password entered by the user and compare with stored hash
    salt = base64.b64decode(user["salt"])
    hashed_password = pbkdf2(password, salt)
    
    if hashed_password != user["password"]:
        print("❌ Incorrect password.")
        return
    
    # Generate TOTP object with correct interval (DO NOT change to 300)
    otp_secret = user["otp_secret"]
    totp = pyotp.TOTP(otp_secret)  # Correctly define totp here

    # Verify OTP with a slight time drift allowance
    otp = input("Enter OTP: ").strip()
    if totp.verify(otp, valid_window=2):  # Allows OTPs from last 2 intervals (~1 min tolerance)
        print("\n✅ Login successful!")
    else:
        print("❌ Invalid OTP or OTP has expired. Please try again.")



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
        print("❌ Invalid option. Exiting.")
        exit()

# Run the application
if __name__ == "__main__":
    main_menu()
