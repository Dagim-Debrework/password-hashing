use std::io::{self, Write};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;

const SALT_SIZE: usize = 16;
const HASH_SIZE: usize = 32;
const ITERATIONS: u32 = 100_000;

fn store_password(password: &str) -> ([u8; SALT_SIZE], [u8; HASH_SIZE]) {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut hash = [0u8; HASH_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut hash);

    (salt, hash)
}

fn verify_password(salt: &[u8], stored_hash: &[u8], password: &str) -> bool {
    let mut hash = [0u8; HASH_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut hash);
    hash == stored_hash
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    print!("Enter your password to store securely: ");
    io::stdout().flush().unwrap();

    let mut user_password = String::new();
    io::stdin().read_line(&mut user_password).expect("Failed to read password");
    let user_password = user_password.trim();

    let (salt, hash) = store_password(user_password);

    println!("\n--- Data Stored in Database ---");
    println!("Original Password: {}", user_password);
    println!("Stored Salt: {}", to_hex(&salt));
    println!("Stored Hash: {}", to_hex(&hash));

    print!("\nRe-enter your password for verification: ");
    io::stdout().flush().unwrap();

    let mut check_password = String::new();
    io::stdin().read_line(&mut check_password).expect("Failed to read password");
    let check_password = check_password.trim();

    if verify_password(&salt, &hash, check_password) {
        println!("✓ Correct password! Access granted.");
    } else {
        println!("✗ Incorrect password! Access denied.");
    }
}
