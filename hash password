import hashlib
import os

def store_password(password):
    """Generate a salted hash for secure password storage."""
    # Generate random 16-byte salt
    salt = os.urandom(16)

    # Hash password with PBKDF2-HMAC-SHA256 (100,000 iterations)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )

    # Return salt and hash as hex strings
    return {
        "salt": salt.hex(),
        "hash": hashed_password.hex()
    }

def verify_password(stored_data, password_to_check):
    """Verify if the provided password matches the stored hash."""
    # Convert stored salt back to bytes
    salt = bytes.fromhex(stored_data['salt'])

    # Hash the input password with the same salt and parameters
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_to_check.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )

    # Compare hashes
    return hashed_password.hex() == stored_data['hash']

# Store password
user_password = input("Enter your password to store securely: ")
stored_data = store_password(user_password)

print("--- Data Stored in Database ---")
print(f"Original Password: {user_password}")
print(f"Stored Salt: {stored_data['salt']}")
print(f"Stored Hash: {stored_data['hash']}")

# Verify password
check_password = input("Re-enter your password for verification: ")

if verify_password(stored_data, check_password):
    print("✓ Correct password! Access granted.")
else:
    print("✗ Incorrect password! Access denied.")
