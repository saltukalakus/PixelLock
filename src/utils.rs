use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit}; 
use image::{GenericImageView}; 
use std::{fs, path::{Path, PathBuf}}; 
use argon2::{Argon2, PasswordHasher}; 
use argon2::password_hash::{SaltString}; 
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose}; 

// Removed: mod error_types;
use crate::error_types::CryptoImageError; // Changed to use crate::error_types

// Length of the salt string when encoded in Base64. Argon2 default is 22 characters for a 16-byte salt.
pub const SALT_STRING_LEN: usize = 22;
// Standard nonce length for AES-GCM, which is 12 bytes (96 bits).
pub const NONCE_STRING_LEN: usize = 12; // Nonce length for AES-GCM

/// Decrypts an image file that was previously encrypted by `encrypt_image`.
/// It handles both Base64 encoded text files and steganographic PNG files.
///
/// # Arguments
/// * `input_encrypted_path_ref` - Path to the encrypted file (.txt or .png).
/// * `output_decrypted_path_base` - Base path for the output decrypted file. The extension will be auto-detected.
/// * `secret` - The user-provided secret (password) for decryption.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(CryptoImageError)` on failure.
pub fn decrypt_image<PIn: AsRef<Path> + std::fmt::Debug, POut: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: PIn,
    output_decrypted_path_base: POut,
    secret: &Zeroizing<String>,
) -> Result<(), CryptoImageError> { // Changed return type
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload: Vec<u8>;

    // Determine input format and extract raw payload.
    if input_extension == "txt" {
        // Read Base64 encoded data from .txt file.
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?; // Uses From<std::io::Error>
        encrypted_file_data_payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())?; // Uses From<Base64DecodeError>
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
    } else if input_extension == "png" {
        // Extract embedded data from steganographic PNG file.
        let carrier_image = image::open(input_encrypted_path)?; // Uses From<ImgError>
        let (width, height) = carrier_image.dimensions();
        
        let mut extracted_bytes_buffer = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        let mut bytes_extracted_count = 0;

        // Stage 1: Extract Header (5 bytes: 1 for LSB config, 4 for payload length)
        // Header is always extracted using 1 LSB per channel.
        let lsb_bits_for_header: u8 = 1;
        let data_extract_mask_header: u8 = (1 << lsb_bits_for_header) - 1;
        let header_len_bytes: usize = 5;
        
        println!("Attempting to extract steganography header ({} bytes using {} LSB/channel)...", header_len_bytes, lsb_bits_for_header);

        'header_extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0;
                for &channel_value in pixel_channels.iter().take(3) {
                    for bit_k in 0..lsb_bits_for_header {
                        let current_extracted_bit = (channel_value >> bit_k) & data_extract_mask_header; // Mask ensures we only consider relevant bits if lsb_bits_for_header > 1, though it's 1 here.
                                                                                                    // For LSB=1, (val >> 0) & 1 is just val & 1.
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            extracted_bytes_buffer.push(current_reconstructed_byte);
                            bytes_extracted_count += 1;
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if bytes_extracted_count == header_len_bytes {
                                break 'header_extraction_loop;
                            }
                        }
                    } // Closes `for bit_k` loop
                    if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
                } // <<< This closing brace was missing for the `for &channel_value` loop
                 if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
            }
             if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
        }

        if bytes_extracted_count < header_len_bytes {
            return Err(CryptoImageError::Steganography( // Changed
                format!("Steganography PNG too small to extract full header. Expected {} bytes, got {}.", header_len_bytes, bytes_extracted_count),
            ));
        }
        
        let lsb_bits_for_payload = extracted_bytes_buffer[0];
        if !(1..=4).contains(&lsb_bits_for_payload) {
            return Err(CryptoImageError::Steganography( // Changed
                format!("Invalid LSB configuration in steganography header: {} (must be 1-4).", lsb_bits_for_payload),
            ));
        }

        let payload_len_arr: [u8; 4] = extracted_bytes_buffer[1..5].try_into()
            .map_err(|_| CryptoImageError::Steganography("Failed to convert extracted payload length bytes.".to_string()))?; // Changed
        let payload_len = u32::from_be_bytes(payload_len_arr) as usize;
        
        println!("Header extracted: LSBs for payload = {}, Payload length = {}. Attempting to extract payload...", lsb_bits_for_payload, payload_len);

        // Stage 2: Extract Payload
        // current_reconstructed_byte and bits_in_current_byte are already reset or hold partial bits from header extraction's end.
        // We need to know the exact pixel and channel where header extraction stopped.
        // For simplicity, we restart pixel iteration but skip pixels already processed for header.
        // This is inefficient. A better way is to continue from the exact bit position.

        // Let's refine to continue from the exact position.
        // We need to track current x, y, channel_idx from header loop.
        // The previous loop structure is better: iterate pixels, and inside, decide if extracting header or payload.
        // Re-doing extraction loop structure:

        let mut all_extracted_data_bytes = Vec::new();
        current_reconstructed_byte = 0; // Reset for clarity, though might carry over if header extraction didn't end on a byte boundary.
        bits_in_current_byte = 0;       // This is critical.
        bytes_extracted_count = 0;      // Counts bytes for the current stage (header then payload)

        let mut lsb_config_for_payload_opt: Option<u8> = None;
        let mut actual_payload_len_opt: Option<usize> = None;
        let mut extracting_header_stage = true;
        
        // Calculate starting pixel/channel for payload if we were to optimize.
        // For now, a single loop that changes behavior.

        'full_extraction_loop: for y_img in 0..height {
            for x_img in 0..width {
                let pixel_channels_val = carrier_image.get_pixel(x_img, y_img).0;
                for &channel_val_pix in pixel_channels_val.iter().take(3) { // Changed from range loop
                    let lsb_to_use_now = if extracting_header_stage { // Initialized directly
                        lsb_bits_for_header
                    } else {
                        lsb_config_for_payload_opt.unwrap_or(1) // Should be set
                    };

                    // let channel_val_pix = pixel_channels_val[channel_idx_val]; // Removed, loop var is now channel_val_pix
                    for bit_k_idx in 0..lsb_to_use_now {
                        let current_extracted_bit = (channel_val_pix >> bit_k_idx) & 1; // Always extract one bit at a time from LSBs
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            all_extracted_data_bytes.push(current_reconstructed_byte);
                            bytes_extracted_count += 1; // This counts bytes for the current stage
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if extracting_header_stage && bytes_extracted_count == header_len_bytes {
                                // Header fully extracted
                                let lsb_val = all_extracted_data_bytes[0];
                                if !(1..=4).contains(&lsb_val) {
                                     return Err(CryptoImageError::Steganography( // Changed
                                        format!("Invalid LSB config in header: {}", lsb_val)));
                                }
                                lsb_config_for_payload_opt = Some(lsb_val);

                                let len_arr_payload: [u8; 4] = all_extracted_data_bytes[1..5].try_into().unwrap();
                                actual_payload_len_opt = Some(u32::from_be_bytes(len_arr_payload) as usize);
                                
                                println!("Steg Header Decoded: LSBs for payload: {}, Payload length: {}", lsb_val, actual_payload_len_opt.unwrap());

                                extracting_header_stage = false;
                                bytes_extracted_count = 0; // Reset for payload byte count
                                all_extracted_data_bytes.clear(); // Clear buffer, it was for header

                                if actual_payload_len_opt.unwrap() == 0 {
                                    break 'full_extraction_loop; // No payload to extract
                                }
                            } else if !extracting_header_stage &&
                                      actual_payload_len_opt == Some(bytes_extracted_count)
                            {
                                // Payload fully extracted
                                break 'full_extraction_loop;
                            }
                        }
                    }
                     // Check after each channel if done
                    if !extracting_header_stage &&
                       actual_payload_len_opt.is_some_and(|len_val|
                           bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0)
                       )
                    {
                        break 'full_extraction_loop;
                    }
                }
                // Check after each pixel if done
                if !extracting_header_stage &&
                   actual_payload_len_opt.is_some_and(|len_val|
                       bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0)
                   )
                {
                    break 'full_extraction_loop;
                }
            }
        }

        if extracting_header_stage || lsb_config_for_payload_opt.is_none() || actual_payload_len_opt.is_none() {
            return Err(CryptoImageError::Steganography( // Changed
                "Failed to extract steganography header or determine payload parameters.".to_string(),
            ));
        }
        
        let final_payload_len = actual_payload_len_opt.unwrap();
        if all_extracted_data_bytes.len() < final_payload_len {
             return Err(CryptoImageError::Steganography( // Changed
                format!("Steganography PNG data incomplete. Expected {} payload bytes, extracted {}.", final_payload_len, all_extracted_data_bytes.len()),
            ));
        }
        
        encrypted_file_data_payload = all_extracted_data_bytes; // These are the actual payload bytes
        println!("Decrypting from Steganography PNG file (LSB {}): {:?}", lsb_config_for_payload_opt.unwrap(), input_encrypted_path);

    } else {
        return Err(CryptoImageError::InvalidParameter( // Changed
            format!("Unsupported input file type for decryption: .{}", input_extension)
        ));
    }

    // Validate payload length.
    if encrypted_file_data_payload.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(CryptoImageError::Decryption("Extracted encrypted data is too short".to_string())); // Changed
    }
    // Split the payload into salt, nonce, and ciphertext.
    let (salt_string_bytes, rest) = encrypted_file_data_payload.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    // Convert salt bytes (which are Base64 string representation) back to SaltString.
    let salt_str = std::str::from_utf8(salt_string_bytes)?; // Uses From<std::str::Utf8Error>
    let salt = SaltString::from_b64(salt_str)?; // Uses From<PasswordHashError>

    // Derive the decryption key using the extracted salt and user's secret.
    let derived_key = derive_encryption_key_with_salt(secret, &salt)?; // Changed

    // Initialize AES-256-GCM cipher.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    // Decrypt the ciphertext.
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoImageError::Decryption("AEAD decryption failed (possibly wrong secret or corrupted file)".to_string()))?; // Changed
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());

    // Attempt to detect the file format of the decrypted data and save with the correct extension.
    if let Some(format) = detect_file_format(&decrypted_data) {
        let final_output_path = output_decrypted_path_base_buf.with_extension(format);
        println!("Detected file format: {:?}. Saving decrypted file to: {:?}", format, final_output_path);
        fs::write(&final_output_path, decrypted_data)
            .map_err(CryptoImageError::Io)?;
    } else {
        eprintln!("Warning: Could not detect file format. Saving decrypted data as is to: {:?}", output_decrypted_path_base_buf);
        fs::write(&output_decrypted_path_base_buf, decrypted_data)
            .map_err(CryptoImageError::Io)?;
    }

    Ok(())
}

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
        match validate_password_complexity("validpass123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one uppercase letter."),
            _ => panic!("Test failed: no_uppercase"),
        }
        // Missing lowercase
        match validate_password_complexity("VALIDPASS123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one lowercase letter."),
            _ => panic!("Test failed: no_lowercase"),
        }
        // Missing digit
        match validate_password_complexity("ValidPassword!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one digit."),
            _ => panic!("Test failed: no_digit"),
        }
        // Missing symbol
        match validate_password_complexity("ValidPassword123") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one symbol (e.g., !@#$%^&*)."),
            _ => panic!("Test failed: no_symbol"),
        }
    }
}
