use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::{ImageError, RgbImage, GenericImageView, ImageFormat};
use rand::{rngs::OsRng, Rng, random};
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
    output_format_preference: &str,
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
    let encrypted_data_core = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encryption failed".to_string(),
        )))?;

    let salt_bytes_to_store = salt.as_bytes();
    assert_eq!(salt_bytes_to_store.len(), SALT_STRING_LEN, "Generated salt string length does not match expected SALT_STRING_LEN.");

    let mut raw_output_payload = Vec::new();
    raw_output_payload.extend_from_slice(salt_bytes_to_store);
    raw_output_payload.extend_from_slice(&nonce_bytes);
    raw_output_payload.extend_from_slice(&encrypted_data_core);
    
    let output_path_base = PathBuf::from(output_encrypted_path_param.as_ref());

    if output_format_preference == "txt" {
        let base64_encoded_data = general_purpose::STANDARD.encode(&raw_output_payload);
        let final_output_path = output_path_base.with_extension("txt");
        fs::write(&final_output_path, base64_encoded_data)?;
        println!("Image encrypted successfully to (Base64 TXT): {:?}", final_output_path);
    } else if output_format_preference == "png" {
        let payload_len_bytes = (raw_output_payload.len() as u32).to_be_bytes();
        let mut data_to_embed = Vec::with_capacity(4 + raw_output_payload.len());
        data_to_embed.extend_from_slice(&payload_len_bytes);
        data_to_embed.extend_from_slice(&raw_output_payload);

        let bytes_to_embed_count = data_to_embed.len();
        let pixels_needed = (bytes_to_embed_count + 2) / 3;

        let width = (pixels_needed as f64).sqrt().ceil() as u32;
        let height = (pixels_needed + width as usize - 1) / width as usize;
        let width = width as u32;
        let height = height as u32;

        if width == 0 || height == 0 {
            return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                image::error::ParameterErrorKind::Generic(
                    "Calculated image dimensions for steganography are zero. Payload might be empty.".to_string()
                )
            )));
        }
        
        let mut carrier_image = RgbImage::new(width, height);
        let mut data_iter = data_to_embed.iter();

        for y in 0..height {
            for x in 0..width {
                let r = *data_iter.next().unwrap_or(&random::<u8>());
                let g = *data_iter.next().unwrap_or(&random::<u8>());
                let b = *data_iter.next().unwrap_or(&random::<u8>());
                carrier_image.put_pixel(x, y, image::Rgb([r, g, b]));
            }
        }
        
        let final_output_path = output_path_base.with_extension("png");
        carrier_image.save(&final_output_path)?;
        println!("Image encrypted successfully to (Steganography PNG): {:?}", final_output_path);
    } else {
        return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
            image::error::ParameterErrorKind::Generic(format!("Unsupported output format: {}", output_format_preference))
        )));
    }

    Ok(original_format_str)
}

pub fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: P,
    output_decrypted_path_base: P,
    secret: &Zeroizing<String>,
) -> Result<(), ImageError> {
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload: Vec<u8>;

    if input_extension == "txt" {
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?;
        encrypted_file_data_payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())
            .map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Unknown,
                format!("Base64 decoding failed for .txt file: {}", e),
            )))?;
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
    } else if input_extension == "png" {
        let carrier_image = image::open(input_encrypted_path)?;
        let (width, height) = carrier_image.dimensions();
        let mut extracted_bytes_with_len = Vec::new();
        
        let max_possible_bytes = (width * height * 3) as usize;

        for y in 0..height {
            for x in 0..width {
                let pixel = carrier_image.get_pixel(x, y);
                extracted_bytes_with_len.push(pixel[0]);
                if extracted_bytes_with_len.len() >= max_possible_bytes { break; }
                extracted_bytes_with_len.push(pixel[1]);
                if extracted_bytes_with_len.len() >= max_possible_bytes { break; }
                extracted_bytes_with_len.push(pixel[2]);
                if extracted_bytes_with_len.len() >= max_possible_bytes { break; }
            }
            if extracted_bytes_with_len.len() >= max_possible_bytes { break; }
        }

        if extracted_bytes_with_len.len() < 4 {
            return Err(ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Exact(ImageFormat::Png),
                "Steganography PNG too small to contain payload length".to_string(),
            )));
        }

        let payload_len_bytes: [u8; 4] = extracted_bytes_with_len[0..4].try_into().unwrap();
        let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;

        if 4 + payload_len > extracted_bytes_with_len.len() {
            return Err(ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Exact(ImageFormat::Png),
                format!("Steganography PNG data incomplete. Expected {} bytes payload, found less after extracting length.", payload_len),
            )));
        }
        encrypted_file_data_payload = extracted_bytes_with_len[4..4 + payload_len].to_vec();
        println!("Decrypting from Steganography PNG file: {:?}", input_encrypted_path);
    } else {
        return Err(ImageError::Unsupported(image::error::UnsupportedError::from_format_and_kind(
            image::error::ImageFormatHint::Unknown,
            image::error::UnsupportedErrorKind::Format(image::error::ImageFormatHint::Exact(image::ImageFormat::from_extension(input_extension).unwrap_or(image::ImageFormat::Png))),
        )));
    }

    if encrypted_file_data_payload.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Extracted encrypted data is too short".to_string(),
        )));
    }
    let (salt_string_bytes, rest) = encrypted_file_data_payload.split_at(SALT_STRING_LEN);
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
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());

    if let Some(format) = detect_file_format(&decrypted_data) {
        let final_output_path = output_decrypted_path_base_buf.with_extension(format);
        println!("Detected file format: {:?}. Saving decrypted file to: {:?}", format, final_output_path);
        fs::write(&final_output_path, decrypted_data)
            .map_err(ImageError::IoError)?;
    } else {
        eprintln!("Warning: Could not detect file format. Saving decrypted data as is to: {:?}", output_decrypted_path_base_buf);
        fs::write(&output_decrypted_path_base_buf, decrypted_data)
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
