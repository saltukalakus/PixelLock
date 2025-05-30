use argon2::{Argon2, PasswordHasher}; 
use argon2::password_hash::{SaltString}; 

use crate::error_types::CryptoImageError; 

pub const SALT_STRING_LEN: usize = 22;
pub const NONCE_STRING_LEN: usize = 12; 

/// Detects common image file formats based on magic bytes.
///
/// # Arguments
/// * `decrypted_data` - A byte slice of the data to check.
///
/// # Returns
/// * `Some(&'static str)` containing the file extension (e.g., "jpeg", "png") if a known format is detected.
/// * `None` if the format is not recognized.
pub fn detect_file_format(decrypted_data: &[u8]) -> Option<&'static str> {
    if decrypted_data.starts_with(&[0xFF, 0xD8, 0xFF]) { // JPEG
        Some("jpeg")
    } else if decrypted_data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) { // PNG
        Some("png")
    } else if decrypted_data.starts_with(b"BM") { // BMP
        Some("bmp")
    } else if decrypted_data.starts_with(b"GIF87a") || decrypted_data.starts_with(b"GIF89a") { // GIF
        Some("gif")
    } else if decrypted_data.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || decrypted_data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) { // TIFF
        Some("tiff")
    } else if decrypted_data.len() >= 12 && 
              decrypted_data.starts_with(b"RIFF") && 
              &decrypted_data[8..12] == b"WEBP" { // WEBP
        Some("webp")
    } else {
        None
    }
}

/// Derives a 32-byte encryption key from a secret (password) and a salt using Argon2id.
///
/// # Arguments
/// * `secret` - The user-provided secret string.
/// * `salt` - The `SaltString` to use for key derivation.
///
/// # Returns
/// * A 32-byte array representing the derived key.
pub fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> Result<[u8; 32], CryptoImageError> { // Changed return type
    // Use Argon2id (default for Argon2 crate).
    let argon2 = Argon2::default();

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
        let salt = SaltString::from_b64("gIq+kM3PS2s7gKbtLgGjGA").unwrap(); // Fixed salt for testing

        let key1 = derive_encryption_key_with_salt(secret, &salt).unwrap(); // Updated to unwrap Result
        let key2 = derive_encryption_key_with_salt(secret, &salt).unwrap(); // Updated to unwrap Result

        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2, "Key derivation should be deterministic for the same secret and salt.");
    }

    #[test]
    fn test_detect_file_format_known() {
        assert_eq!(detect_file_format(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpeg"));
        assert_eq!(detect_file_format(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]), Some("png"));
        assert_eq!(detect_file_format(b"BMxxxx"), Some("bmp")); // "xxxx" are placeholders for size etc.
        assert_eq!(detect_file_format(b"GIF89a"), Some("gif"));
        assert_eq!(detect_file_format(&[0x49, 0x49, 0x2A, 0x00]), Some("tiff")); // TIFF Little Endian
        assert_eq!(detect_file_format(&[0x4D, 0x4D, 0x00, 0x2A]), Some("tiff")); // TIFF Big Endian
        assert_eq!(detect_file_format(b"RIFFxxxxWEBPVP8 "), Some("webp")); // "xxxx" and "VP8 " are part of WEBP
    }

    #[test]
    fn test_detect_file_format_unknown() {
        assert_eq!(detect_file_format(b"this is not an image"), None);
        assert_eq!(detect_file_format(&[0x01, 0x02, 0x03, 0x04]), None);
    }

    #[test]
    fn test_validate_password_complexity_valid() {
        assert!(validate_password_complexity("ValidPass123!@#$").is_ok()); // Changed: Added '$' to make length 16
        assert!(validate_password_complexity("Another_Good-Password456$").is_ok());
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
}
