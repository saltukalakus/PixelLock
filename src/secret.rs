use argon2::{Argon2, PasswordHasher, Algorithm, Version}; 
use argon2::password_hash::{SaltString};

use crate::error_types::CryptoImageError; 

/// Derives a 32-byte encryption key from a secret (password) and a salt using Argon2id.
///
/// # Arguments
/// * `secret` - The user-provided secret string.
/// * `salt` - The `SaltString` to use for key derivation.
///
/// # Returns
/// * A 32-byte array representing the derived key.
pub fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> Result<[u8; 32], CryptoImageError> {
    // Configure Argon2 parameters
    let m_cost = 65536; // 64 MiB
    let t_cost = 10;  // 10 iterations
    let p_cost = 4;   // 4 lanes (parallelism)
    let output_len = 32; // For AES-256

    // argon2::Params::new returns Result<Params, password_hash::errors::InvalidParams>
    // We use the From<password_hash::errors::InvalidParams> for argon2::Error trait
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(output_len))
        .map_err(CryptoImageError::Argon2)?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    // Hash the password with the salt.
    let password_hash = argon2
        .hash_password(secret.as_bytes(), salt)?; // Uses From<Argon2Error>

    // Extract the raw hash output.
    let derived_key_output = password_hash.hash.ok_or_else(|| CryptoImageError::Encryption("Argon2 password hash output is unexpectedly None".to_string()))?;
    let key_bytes = derived_key_output.as_bytes();

    // Argon2 output can be longer than 32 bytes depending on params; we take the first 32 bytes for AES-256.
    key_bytes[..32].try_into().map_err(CryptoImageError::from) // Explicitly map TryFromSliceError
}

/// Validates the complexity of a given password.
///
/// # Arguments
/// * `password` - The password string to validate.
///
/// # Returns
/// * `true` if the password meets all complexity requirements.
/// * `false` otherwise, and prints an error message.
pub fn validate_password_complexity(password: &str) -> Result<(), CryptoImageError> {
    // Check minimum length.
    if password.len() < 16 {
        return Err(CryptoImageError::PasswordComplexity("Password must be at least 16 characters long.".to_string()));
    }
    // Check for character types.
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_ascii_alphanumeric());

    if !has_uppercase {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one uppercase letter.".to_string()));
    }
    if !has_lowercase {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one lowercase letter.".to_string()));
    }
    if !has_digit {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one digit.".to_string()));
    }
    if !has_symbol {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one symbol (e.g., !@#$%^&*).".to_string()));
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    // Removed: use tempfile::tempdir; 
    // Removed: fn create_dummy_png ...

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let secret = "test_password";
        // Use SaltString::from_b64 with a valid 22-character PHC Base64 salt string.
        let salt_str = "AAAAAAAAAAAAAAAAAAAAAA"; // Represents 16 zero bytes
        let salt = SaltString::from_b64(salt_str)
            .expect("Failed to create SaltString from PHC valid string");

        let key1 = derive_encryption_key_with_salt(secret, &salt).unwrap();
        let key2 = derive_encryption_key_with_salt(secret, &salt).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2, "Key derivation should be deterministic for the same secret and salt.");
    }

    #[test]
    fn test_derive_encryption_key_different_salt() {
        let secret = "test_password";
        // Use SaltString::from_b64 with different valid 22-character PHC Base64 salt strings.
        let salt_str1 = "AAAAAAAAAAAAAAAAAAAAAA"; // Represents 16 zero bytes
        let salt_str2 = "/////////////////////w"; // Represents 16 0xFF bytes
        
        let salt1 = SaltString::from_b64(salt_str1)
            .expect("Failed to create SaltString for salt1");
        let salt2 = SaltString::from_b64(salt_str2)
            .expect("Failed to create SaltString for salt2");

        let key1 = derive_encryption_key_with_salt(secret, &salt1).unwrap();
        let key2 = derive_encryption_key_with_salt(secret, &salt2).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2, "Keys derived with different salts should not be the same.");
    }

    #[test]
    fn test_derive_encryption_key_different_secret() {
        let secret1 = "test_password_A";
        let secret2 = "test_password_B"; // Different secret
        let salt_str = "AAAAAAAAAAAAAAAAAAAAAA";
        let salt = SaltString::from_b64(salt_str)
            .expect("Failed to create SaltString");

        let key1 = derive_encryption_key_with_salt(secret1, &salt).unwrap();
        let key2 = derive_encryption_key_with_salt(secret2, &salt).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2, "Keys derived with different secrets should not be the same.");
    }

    #[test]
    fn test_derive_encryption_key_empty_secret() {
        let secret = ""; // Empty secret
        let salt_str = "AAAAAAAAAAAAAAAAAAAAAA";
        let salt = SaltString::from_b64(salt_str)
            .expect("Failed to create SaltString");
        
        // Argon2 should still produce a hash for an empty password.
        let key_result = derive_encryption_key_with_salt(secret, &salt);
        assert!(key_result.is_ok(), "Deriving key with empty secret should succeed. Error: {:?}", key_result.err());
        assert_eq!(key_result.unwrap().len(), 32);
    }

    #[test]
    fn test_validate_password_complexity_valid() {
        assert!(validate_password_complexity("ValidPass123!@#$").is_ok()); // Changed: Added '$' to make length 16
        assert!(validate_password_complexity("Another_Good-Password456$").is_ok());
    }

    #[test]
    fn test_validate_password_complexity_exactly_16_chars_valid() {
        assert!(validate_password_complexity("ValidPass123!@#$").is_ok()); // Exactly 16
    }

    #[test]
    fn test_validate_password_complexity_too_short() {
        match validate_password_complexity("Short1!") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must be at least 16 characters long.");
            }
            _ => panic!("Expected PasswordComplexity error for short password."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_uppercase() {
        match validate_password_complexity("nouppercase123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one uppercase letter.");
            }
            _ => panic!("Expected PasswordComplexity error for no uppercase."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_lowercase() {
        match validate_password_complexity("NOLOWERCASE123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one lowercase letter.");
            }
            _ => panic!("Expected PasswordComplexity error for no lowercase."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_digit() {
        match validate_password_complexity("NoDigitPassword!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one digit.");
            }
            _ => panic!("Expected PasswordComplexity error for no digit."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_symbol() {
        match validate_password_complexity("NoSymbolPassword123") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one symbol (e.g., !@#$%^&*).");
            }
            _ => panic!("Expected PasswordComplexity error for no symbol."),
        }
    }

    #[test]
    fn test_validate_password_complexity_all_criteria_missing_sequentially() {
        // Too short
        match validate_password_complexity("Pass1!") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must be at least 16 characters long."),
            _ => panic!("Test failed: too_short"),
        }
        // Missing uppercase
        match validate_password_complexity("validpass123!@#a") { // Changed: Length 16. No uppercase.
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one uppercase letter."),
            _ => panic!("Test failed: no_uppercase"),
        }
        // Missing lowercase
        match validate_password_complexity("VALIDPASS123!@#A") { // Changed: Length 16. No lowercase.
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one lowercase letter."),
            _ => panic!("Test failed: no_lowercase"),
        }
        // Missing digit
        match validate_password_complexity("ValidPassword!@#") { // Length 16. No digit.
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one digit."),
            _ => panic!("Test failed: no_digit"),
        }
        // Missing symbol
        match validate_password_complexity("ValidPassword123") { // Length 16. No symbol.
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one symbol (e.g., !@#$%^&*)."),
            _ => panic!("Test failed: no_symbol"),
        }
    }

    #[test]
    fn test_validate_password_complexity_missing_multiple_criteria() {
        // Missing lowercase and digit
        match validate_password_complexity("AAAAAAAAAAAAAAA!") { // Length 16, has uppercase, has symbol
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                // The order of checks matters, it will report the first failure.
                assert!(msg.contains("lowercase letter") || msg.contains("digit"));
            }
            _ => panic!("Expected PasswordComplexity error."),
        }

        // Missing uppercase and symbol
        match validate_password_complexity("aaaaaaaaaaaaaaa1") { // Length 16, has lowercase, has digit
             Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert!(msg.contains("uppercase letter") || msg.contains("symbol"));
            }
            _ => panic!("Expected PasswordComplexity error."),
        }
    }

    #[test]
    fn test_validate_password_complexity_with_non_ascii_chars() {
        // Current validation is ASCII specific. Non-ASCII might pass or fail based on their category.
        // This test is more for observing behavior if requirements change.
        // Example: "ValidPass123!@#$€" (Euro sign is not ASCII punctuation/graphic)
        // This should still pass if the ASCII parts meet criteria and length is sufficient.
        assert!(validate_password_complexity("ValidPass123!@#$€").is_ok());

        // Example: "パスワードパスワードパスワードA1!" - Japanese password.
        // Length: 17 (OK)
        // Uppercase: 'A' (OK)
        // Lowercase: No ASCII lowercase. (FAILS HERE)
        // Digit: '1' (OK)
        // Symbol: '!' (OK)
        match validate_password_complexity("パスワードパスワードパスワードA1!") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                 assert_eq!(msg, "Password must contain at least one lowercase letter.");
            }
            _ => panic!("Expected PasswordComplexity error for non-ASCII password missing ASCII lowercase letter."),
        }
    }
}