use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::{ImageError};
use rand::{rngs::OsRng, Rng};
use std::{fs, path::{Path, PathBuf}};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

pub const SALT_STRING_LEN: usize = 22;
pub const NONCE_STRING_LEN: usize = 12; // Nonce length for AES-GCM

pub fn encrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P,
    output_encrypted_path_param: P,
    secret: &Zeroizing<String>,
) -> Result<String, ImageError> {
    let original_format_str = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("png")
        .to_lowercase();

    let img_bytes = fs::read(&input_image_path)
        .map_err(ImageError::IoError)?;

    let salt: SaltString = SaltString::generate(&mut OsRng);
    let derived_key = derive_encryption_key_with_salt(&*secret, &salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encryption failed".to_string(),
        )))?;

    let salt_bytes_to_store = salt.as_bytes();
    assert_eq!(salt_bytes_to_store.len(), SALT_STRING_LEN, "Generated salt string length does not match expected SALT_STRING_LEN.");

    let mut output_bytes = Vec::new();
    output_bytes.extend_from_slice(salt_bytes_to_store);
    output_bytes.extend_from_slice(&nonce_bytes);
    output_bytes.extend_from_slice(&encrypted_data);

    let base64_encoded_data = general_purpose::STANDARD.encode(&output_bytes);

    let output_path_buf = PathBuf::from(output_encrypted_path_param.as_ref());
    let final_output_path = output_path_buf.with_extension("txt");

    fs::write(&final_output_path, base64_encoded_data)?;
    println!("Image encrypted successfully to: {:?}", final_output_path);
    Ok(original_format_str)
}

pub fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path: P,
    output_decrypted_path: P,
    secret: &Zeroizing<String>,
) -> Result<(), ImageError> {
    let encrypted_file_content = fs::read_to_string(&input_encrypted_path)?;

    let encrypted_file_data = general_purpose::STANDARD.decode(encrypted_file_content.trim())
        .map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            format!("Base64 decoding failed: {}", e),
        )))?;

    if encrypted_file_data.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encrypted file is too short".to_string(),
        )));
    }
    let (salt_string_bytes, rest) = encrypted_file_data.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    let salt_str = std::str::from_utf8(salt_string_bytes).map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, "Invalid salt UTF-8".to_string()
    )))?;
    let salt = SaltString::new(salt_str).map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, format!("Invalid salt format: {}", e)
    )))?;

    let derived_key = derive_encryption_key_with_salt(&*secret, &salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Decryption failed (possibly wrong secret or corrupted file)".to_string(),
        )))?;

    if let Some(format) = detect_file_format(&decrypted_data) {
        let output_path = output_decrypted_path.as_ref().with_extension(format);
        println!("Detected file format: {:?}. Saving decrypted file to: {:?}", format, output_path);
        fs::write(&output_path, decrypted_data)
            .map_err(ImageError::IoError)?;
    } else {
        eprintln!("Warning: Could not detect file format. Saving decrypted data as is to: {:?}", output_decrypted_path.as_ref());
        fs::write(output_decrypted_path.as_ref(), decrypted_data)
            .map_err(ImageError::IoError)?;
    }

    Ok(())
}

pub fn detect_file_format(decrypted_data: &[u8]) -> Option<&'static str> {
    if decrypted_data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if decrypted_data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("png")
    } else if decrypted_data.starts_with(&[b'B', b'M']) {
        Some("bmp")
    } else if decrypted_data.starts_with(b"GIF87a") || decrypted_data.starts_with(b"GIF89a") {
        Some("gif")
    } else if decrypted_data.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || decrypted_data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
        Some("tiff")
    } else if decrypted_data.len() >= 12 && 
              decrypted_data.starts_with(b"RIFF") && 
              &decrypted_data[8..12] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}

pub fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> [u8; 32] {
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(secret.as_bytes(), salt)
        .expect("Failed to hash password");

    let derived_key = password_hash.hash.expect("Hash missing in password hash");
    let key_bytes = derived_key.as_bytes();

    key_bytes[..32].try_into().expect("Derived key should be 32 bytes")
}
