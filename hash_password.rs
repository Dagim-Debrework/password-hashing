use std::io::{self, Write};
use rand::Rng;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2
};

/// Generate a salted hash for secure password storage
fn store_password(password: &str) -> (String, String) {
    // Generate random salt
    let salt = SaltString::generate(&mut rand::thread_rng());

    // Hash password with PBKDF2-HMAC-SHA256 (100,000 iterations)
    let password_hash = Pbkdf2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");

    // Extract salt and hash as strings
    let salt_string = salt.to_string();
    let hash_string = password_hash.to_string();

    (salt_string, hash_string)
}

/// Verify if the provided password matches the stored hash
fn verify_password(stored_hash: &str, password_to_check: &str) -> bool {
    // Parse the stored hash
    let parsed_hash = PasswordHash::new(stored_hash)
        .expect("Failed to parse hash");

    // Verify password
    Pbkdf2.verify_password(password_to_check.as_bytes(), &parsed_hash).is_ok()
}

fn main() {
    // Store password
    print!("Enter your password to store securely: ");
    io::stdout().flush().unwrap();

    let mut user_password = String::new();
    io::stdin().read_line(&mut user_password)
        .expect("Failed to read password");
    let user_password = user_password.trim();

    let (salt, hash) = store_password(user_password);

    println!("\n--- Data Stored in Database ---");
    println!("Original Password: {}", user_password);
    println!("Stored Salt: {}", salt);
    println!("Stored Hash: {}", hash);

    // Verify password
    print!("\nRe-enter your password for verification: ");
    io::stdout().flush().unwrap();

    let mut check_password = String::new();
    io::stdin().read_line(&mut check_password)
        .expect("Failed to read password");
    let check_password = check_password.trim();

    if verify_password(&hash, check_password) {
        println!("✓ Correct password! Access granted.");
    } else {
        println!("✗ Incorrect password! Access denied.");
    }
}
