//! Optional app-lock: a password gate on the GUI window itself.
//!
//! This protects casual access to the app UI; it is NOT the encryption key
//! for any volume or file (those live only in the agent). We store an
//! Argon2id PHC hash of the chosen password in the GUI settings and verify
//! against it. The lock screen carries no padlock iconography by request —
//! just a title and a password field.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Hash a new app-lock password (Argon2id PHC string).
pub fn hash_password(password: &str) -> Option<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).ok()?;
    let salt = SaltString::encode_b64(&salt_bytes).ok()?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .ok()
        .map(|h| h.to_string())
}

/// Verify a password against a stored PHC hash.
pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}
