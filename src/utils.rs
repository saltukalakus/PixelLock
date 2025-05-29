use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::{ImageError, RgbImage, GenericImageView, ImageFormat};
use rand::{rngs::OsRng, Rng, random};
use std::{fs, path::{Path, PathBuf}};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

// Length of the salt string when encoded in Base64. Argon2 default is 22 characters for a 16-byte salt.
pub const SALT_STRING_LEN: usize = 22;
// Standard nonce length for AES-GCM, which is 12 bytes (96 bits).
pub const NONCE_STRING_LEN: usize = 12; // Nonce length for AES-GCM

/// Encrypts an image file using AES-256-GCM and optionally embeds it into a carrier PNG image
/// using LSB steganography or saves it as a Base64 encoded text file.
///
/// # Arguments
/// * `input_image_path` - Path to the image to be encrypted.
/// * `output_encrypted_path_param` - Base path for the output encrypted file. Extension will be set based on `output_format_preference`.
/// * `secret` - The user-provided secret (password) for encryption, wrapped in Zeroizing for security.
/// * `output_format_preference` - "txt" for Base64 output, "png" for steganographic PNG output.
/// * `base_image_path_opt` - Optional path to a base PNG image to use as a carrier for steganography.
/// * `lsb_bits_per_channel` - Number of LSBs (1-4) to use per color channel for steganography if `output_format_preference` is "png".
///
/// # Returns
/// * `Ok(String)` containing the original format of the input image on success.
/// * `Err(ImageError)` on failure.
pub fn encrypt_image<P1: AsRef<Path> + std::fmt::Debug, P2: AsRef<Path> + std::fmt::Debug, P3: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P1,
    output_encrypted_path_param: P2,
    secret: &Zeroizing<String>,
    output_format_preference: &str,
    base_image_path_opt: Option<P3>,
    lsb_bits_per_channel: u8, // New parameter
) -> Result<String, ImageError> {
    let original_format_str = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("png")
        .to_lowercase();

    // Read the entire input image file into bytes.
    let img_bytes = fs::read(&input_image_path)
        .map_err(ImageError::IoError)?;

    // Generate a new random salt for Argon2.
    let salt: SaltString = SaltString::generate(&mut OsRng);
    // Derive the encryption key from the secret and salt using Argon2.
    let derived_key = derive_encryption_key_with_salt(secret, &salt);

    // Initialize AES-256-GCM cipher with the derived key.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    // Generate a random nonce for AES-GCM.
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the image data.
    let encrypted_data_core = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encryption failed".to_string(),
        )))?;

    // Get the salt as a Base64 string, then convert to bytes for storage.
    // This ensures the salt is stored in its standard string representation.
    let salt_bytes_to_store = salt.as_str().as_bytes();
    assert_eq!(salt_bytes_to_store.len(), SALT_STRING_LEN, "Generated salt string length does not match expected SALT_STRING_LEN.");

    // Assemble the raw output payload: salt + nonce + encrypted data.
    let mut raw_output_payload = Vec::new();
    raw_output_payload.extend_from_slice(salt_bytes_to_store);
    raw_output_payload.extend_from_slice(&nonce_bytes);
    raw_output_payload.extend_from_slice(&encrypted_data_core);
    
    let output_path_base = PathBuf::from(output_encrypted_path_param.as_ref());

    // Handle output based on the preferred format.
    if output_format_preference == "txt" {
        // Encode the payload to Base64 and save as a .txt file.
        let base64_encoded_data = general_purpose::STANDARD.encode(&raw_output_payload);
        let final_output_path = output_path_base.with_extension("txt");
        fs::write(&final_output_path, base64_encoded_data)?;
        println!("Image encrypted successfully to (Base64 TXT): {:?}", final_output_path);
    } else if output_format_preference == "png" {
        // Embed the payload into a PNG image using LSB steganography.
        // Prepend the payload with its length (4 bytes, big-endian).
        let payload_len_bytes = (raw_output_payload.len() as u32).to_be_bytes();
        let mut data_to_embed = Vec::with_capacity(4 + raw_output_payload.len());
        data_to_embed.extend_from_slice(&payload_len_bytes);
        data_to_embed.extend_from_slice(&raw_output_payload);

        // Calculate total bits to embed and bits available per pixel.
        let total_bits_to_embed = data_to_embed.len() * 8;
        let bits_per_pixel = 3 * lsb_bits_per_channel as usize; // 3 channels (R,G,B)
        if bits_per_pixel == 0 {
            return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                image::error::ParameterErrorKind::Generic("LSB bits per channel cannot be zero.".to_string())
            )));
        }
        // Calculate the number of pixels needed in the carrier image.
        let pixels_needed = total_bits_to_embed.div_ceil(bits_per_pixel);

        let mut carrier_image: RgbImage;

        // Determine the carrier image: use provided base image or generate a new one.
        if let Some(base_path_ref) = base_image_path_opt {
            // Load and prepare the user-provided base image.
            let base_path = base_path_ref.as_ref();
            if !base_path.exists() {
                return Err(ImageError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Base image not found: {:?}", base_path),
                )));
            }
            if base_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() != "png" {
                return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                    image::error::ParameterErrorKind::Generic("Base image must be a PNG file.".to_string())
                )));
            }

            let base_dyn_image = image::open(base_path)?;
            let base_rgb_image = base_dyn_image.to_rgb8();
            let base_width = base_rgb_image.width();
            let base_height = base_rgb_image.height();
            let base_pixels_capacity = (base_width * base_height) as usize;

            if base_pixels_capacity >= pixels_needed {
                // Base image is large enough.
                carrier_image = base_rgb_image;
            } else {
                // Base image is too small, tile it to fit the data.
                let mut new_width = base_width;
                let mut new_height = base_height;
                while ((new_width * new_height) as usize) < pixels_needed {
                    new_width *= 2;
                    new_height *= 2; 
                }
                if new_width == 0 { new_width = (pixels_needed as f64).sqrt().ceil() as u32; }
                if new_height == 0 { new_height = (pixels_needed as u32).div_ceil(new_width); }
                if new_width == 0 { new_width = 1; }
                if new_height == 0 { new_height = 1; }

                let mut tiled_image = RgbImage::new(new_width, new_height);
                // Fill the new tiled image by repeating the base image.
                if base_width > 0 && base_height > 0 {
                    for y_tiled in 0..new_height {
                        for x_tiled in 0..new_width {
                            let orig_x = x_tiled % base_width;
                            let orig_y = y_tiled % base_height;
                            tiled_image.put_pixel(x_tiled, y_tiled, *base_rgb_image.get_pixel(orig_x, orig_y));
                        }
                    }
                } else {
                    // If base image was 0x0, fill with random pixels (edge case).
                    for pixel in tiled_image.pixels_mut() {
                        *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
                    }
                }
                carrier_image = tiled_image;
            }
        } else {
            // No base image provided, generate a new one with random pixel data.
            let width = (pixels_needed as f64).sqrt().ceil() as u32;
            let mut height = (pixels_needed as u32).div_ceil(width);
            if width == 0 { return Err(ImageError::Parameter(image::error::ParameterError::from_kind(image::error::ParameterErrorKind::Generic("Calculated width is zero for new image".into())))); }
            if height == 0 { height = 1; }

            carrier_image = RgbImage::new(width, height);
            // Fill the new image with random pixels.
            for pixel_val in carrier_image.pixels_mut() {
                *pixel_val = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
            }
        }
        
        // Embed data into the carrier image using LSB steganography.
        let mut bit_idx_overall = 0; 
        let (img_width, img_height) = carrier_image.dimensions();
        
        // Mask to clear the LSBs that will be used for data.
        let clear_mask: u8 = 0xFF << lsb_bits_per_channel;
        // Mask to extract the LSBs from the data bits.
        let data_extract_mask: u8 = (1 << lsb_bits_per_channel) - 1;

        'embedding_loop: for y in 0..img_height {
            for x in 0..img_width {
                if bit_idx_overall >= total_bits_to_embed {
                    break 'embedding_loop; // All data embedded.
                }
                let pixel = carrier_image.get_pixel_mut(x, y);
                
                // Iterate over R, G, B channels.
                for channel_idx in 0..3 {
                    if bit_idx_overall >= total_bits_to_embed {
                        break 'embedding_loop; // All data embedded.
                    }
                    
                    // Collect `lsb_bits_per_channel` bits from the data to embed in this channel.
                    let mut bits_for_channel: u8 = 0;
                    for bit_k in 0..lsb_bits_per_channel {
                        if bit_idx_overall < total_bits_to_embed {
                            let data_byte_idx = bit_idx_overall / 8;
                            let bit_in_byte_idx = bit_idx_overall % 8;
                            let current_data_bit = (data_to_embed[data_byte_idx] >> bit_in_byte_idx) & 1;
                            bits_for_channel |= current_data_bit << bit_k;
                            bit_idx_overall += 1;
                        } else {
                            break; // No more data bits to embed.
                        }
                    }
                    // Clear LSBs of the original pixel channel and set the new data bits.
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & clear_mask) | (bits_for_channel & data_extract_mask);
                }
            }
        }
        
        // Ensure all data was embedded.
        if bit_idx_overall < total_bits_to_embed {
            return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                image::error::ParameterErrorKind::Generic("Carrier image too small to embed all data bits.".to_string())
            )));
        }

        // Save the steganographic image.
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
/// * `Err(ImageError)` on failure.
pub fn decrypt_image<PIn: AsRef<Path> + std::fmt::Debug, POut: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: PIn,
    output_decrypted_path_base: POut,
    secret: &Zeroizing<String>,
) -> Result<(), ImageError> {
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload: Vec<u8>;

    // Determine input format and extract raw payload.
    if input_extension == "txt" {
        // Read Base64 encoded data from .txt file.
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?;
        encrypted_file_data_payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())
            .map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Unknown,
                format!("Base64 decoding failed for .txt file: {}", e),
            )))?;
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
    } else if input_extension == "png" {
        // Extract embedded data from steganographic PNG file.
        let carrier_image = image::open(input_encrypted_path)?;
        let (width, height) = carrier_image.dimensions();
        
        // For decryption, assume 1 LSB per channel was used to store the length and payload.
        // This is a fixed assumption for the extraction part. The actual encryption might use more for data,
        // but the length header is assumed to be 1 LSB for robustness.
        // TODO: Consider making LSB bits for length header configurable or stored if encryption uses variable LSBs.
        let lsb_bits_per_channel_decrypt: u8 = 1; 
        let data_extract_mask_decrypt: u8 = (1 << lsb_bits_per_channel_decrypt) - 1;

        let mut extracted_all_bytes = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        
        let mut payload_len_opt: Option<usize> = None;
        let mut bytes_extracted_count = 0;

        // Theoretical maximum bytes that could be stored, as a sanity check.
        let theoretical_max_bytes = (width as usize * height as usize * 3 * lsb_bits_per_channel_decrypt as usize) / 8;


        'extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0; // R, G, B values

                // Iterate over R, G, B channels.
                for &channel_value in pixel_channels.iter().take(3) {
                    // Extract LSBs from the current channel.
                    let extracted_bits_from_channel = channel_value & data_extract_mask_decrypt; 
                    
                    // Reconstruct bytes from the extracted bits.
                    for bit_k in 0..lsb_bits_per_channel_decrypt {
                        let current_extracted_bit = (extracted_bits_from_channel >> bit_k) & 1;
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            // Full byte reconstructed.
                            extracted_all_bytes.push(current_reconstructed_byte);
                            bytes_extracted_count += 1;
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            // After extracting 4 bytes, interpret them as the payload length.
                            if bytes_extracted_count == 4 && payload_len_opt.is_none() {
                                let len_arr: [u8; 4] = extracted_all_bytes[0..4].try_into().map_err(|_| 
                                    ImageError::Decoding(image::error::DecodingError::new(
                                        image::error::ImageFormatHint::Exact(ImageFormat::Png),
                                        "Failed to convert extracted length bytes to array".to_string(),
                                )))?;
                                payload_len_opt = Some(u32::from_be_bytes(len_arr) as usize);
                            }

                            // If payload length is known, stop after extracting all payload bytes.
                            if let Some(len) = payload_len_opt {
                                if bytes_extracted_count >= 4 + len { // 4 bytes for length + payload
                                    break 'extraction_loop;
                                }
                            }
                            
                            // Sanity check against theoretical maximum.
                            if bytes_extracted_count > theoretical_max_bytes + 4 { // +4 for length
                                 return Err(ImageError::Decoding(image::error::DecodingError::new(
                                    image::error::ImageFormatHint::Exact(ImageFormat::Png),
                                    "Potential data corruption: trying to extract more bytes than image capacity.".to_string(),
                                )));
                            }
                        }
                    }
                }
            }
        }
        
        // Ensure payload length was found and enough data was extracted.
        if payload_len_opt.is_none() || extracted_all_bytes.len() < 4 {
             return Err(ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Exact(ImageFormat::Png),
                "Steganography PNG too small to extract payload length".to_string(),
            )));
        }
        let payload_len = payload_len_opt.unwrap();

        if extracted_all_bytes.len() < 4 + payload_len {
             return Err(ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Exact(ImageFormat::Png),
                format!("Steganography PNG data incomplete. Expected {} payload bytes, extracted {}.", payload_len, extracted_all_bytes.len() - 4),
            )));
        }
        // The actual encrypted payload is after the 4-byte length.
        encrypted_file_data_payload = extracted_all_bytes[4..4 + payload_len].to_vec();
        println!("Decrypting from Steganography PNG file (LSB): {:?}", input_encrypted_path);
    } else {
        return Err(ImageError::Unsupported(image::error::UnsupportedError::from_format_and_kind(
            image::error::ImageFormatHint::Unknown,
            image::error::UnsupportedErrorKind::Format(image::error::ImageFormatHint::Exact(image::ImageFormat::from_extension(input_extension).unwrap_or(image::ImageFormat::Png))),
        )));
    }

    // Validate payload length.
    if encrypted_file_data_payload.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Extracted encrypted data is too short".to_string(),
        )));
    }
    // Split the payload into salt, nonce, and ciphertext.
    let (salt_string_bytes, rest) = encrypted_file_data_payload.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    // Convert salt bytes (which are Base64 string representation) back to SaltString.
    let salt_str = std::str::from_utf8(salt_string_bytes).map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, "Invalid salt UTF-8".to_string()
    )))?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, format!("Invalid salt format: {}", e)
    )))?;

    // Derive the decryption key using the extracted salt and user's secret.
    let derived_key = derive_encryption_key_with_salt(secret, &salt);

    // Initialize AES-256-GCM cipher.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    // Decrypt the ciphertext.
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Decryption failed (possibly wrong secret or corrupted file)".to_string(),
        )))?;
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());

    // Attempt to detect the file format of the decrypted data and save with the correct extension.
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
pub fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> [u8; 32] {
    // Use Argon2id (default for Argon2 crate).
    let argon2 = Argon2::default();

    // Hash the password with the salt.
    let password_hash = argon2
        .hash_password(secret.as_bytes(), salt)
        .expect("Failed to hash password");

    // Extract the raw hash output.
    let derived_key_output = password_hash.hash.expect("Hash missing in password hash");
    let key_bytes = derived_key_output.as_bytes();

    // Argon2 output can be longer than 32 bytes depending on params; we take the first 32 bytes for AES-256.
    key_bytes[..32].try_into().expect("Derived key should be 32 bytes")
}

/// Validates the complexity of a given password.
///
/// # Arguments
/// * `password` - The password string to validate.
///
/// # Returns
/// * `true` if the password meets all complexity requirements.
/// * `false` otherwise, and prints an error message.
pub fn validate_password_complexity(password: &str) -> bool {
    // Check minimum length.
    if password.len() < 16 {
        eprintln!("Error: Password must be at least 16 characters long.");
        return false;
    }
    // Check for character types.
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_ascii_alphanumeric());

    if !has_uppercase {
        eprintln!("Error: Password must contain at least one uppercase letter.");
        return false;
    }
    if !has_lowercase {
        eprintln!("Error: Password must contain at least one lowercase letter.");
        return false;
    }
    if !has_digit {
        eprintln!("Error: Password must contain at least one digit.");
        return false;
    }
    if !has_symbol {
        eprintln!("Error: Password must contain at least one symbol (e.g., !@#$%^&*).");
        return false;
    }
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir; // For creating temporary directories for tests

    // Helper function to create a dummy PNG file for testing base image functionality.
    fn create_dummy_png(path: &Path, width: u32, height: u32) -> Result<(), ImageError> {
        let mut img = RgbImage::new(width, height);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
        }
        img.save_with_format(path, ImageFormat::Png)?; // Explicitly save as PNG
        Ok(())
    }

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let secret = "test_password";
        let salt = SaltString::from_b64("gIq+kM3PS2s7gKbtLgGjGA").unwrap(); // Fixed salt for testing

        let key1 = derive_encryption_key_with_salt(secret, &salt);
        let key2 = derive_encryption_key_with_salt(secret, &salt);

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
    fn test_encrypt_decrypt_round_trip_txt() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input.dat");
        let encrypted_path = temp_dir.path().join("test_encrypted"); // Extension added by encrypt_image
        let decrypted_path = temp_dir.path().join("test_decrypted"); // Extension added by decrypt_image

        let original_data = b"This is some test image data for TXT format.";
        fs::write(&input_image_path, original_data)?;

        let secret = Zeroizing::new("supersecretpassword123!@#".to_string());
        let output_format_preference = "txt";
        let lsb_bits: u8 = 1; // Not used for txt, but required by function signature

        // Encrypt
        encrypt_image(
            &input_image_path,
            &encrypted_path, // encrypt_image will add .txt
            &secret,
            output_format_preference,
            None::<PathBuf>, // No base image for txt
            lsb_bits,
        )?;

        let encrypted_file_with_ext = encrypted_path.with_extension("txt");
        assert!(encrypted_file_with_ext.exists(), "Encrypted TXT file should exist.");

        // Decrypt
        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path, // decrypt_image will try to detect extension
            &secret,
        )?;
        
        // Assuming decrypt_image saves with a detected extension or no extension if unknown
        // For this test, we expect it to be raw data, so we check the path without specific extension first
        // or with a common one if detect_file_format returns None and saves as is.
        // Since original_data is not a known image format, detect_file_format will return None.
        // The decrypt_image function will then save it without an extension (using output_decrypted_path_base as is).
        let decrypted_data_content = fs::read(&decrypted_path)?;

        assert_eq!(original_data.to_vec(), decrypted_data_content, "Decrypted data should match original for TXT format.");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_png_no_base() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input_for_png.png"); // Changed .dat to .png
        let encrypted_path_base = temp_dir.path().join("test_encrypted_steg");
        let decrypted_path_base = temp_dir.path().join("test_decrypted_steg");

        // Create a small dummy PNG file as input data to encrypt
        let original_png_width = 10;
        let original_png_height = 5;
        create_dummy_png(&input_image_path, original_png_width, original_png_height)?;
        let original_data = fs::read(&input_image_path)?;

        let secret = Zeroizing::new("anotherStrongPassword!$5^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 1; // Use 1 LSB to match decryption logic assumption

        // Encrypt
        let original_input_format = encrypt_image(
            &input_image_path,
            &encrypted_path_base, // encrypt_image will add .png
            &secret,
            output_format_preference,
            None::<PathBuf>, // No base image
            lsb_bits,
        )?;
        assert_eq!(original_input_format, "png");


        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file should exist.");

        // Decrypt
        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path_base, // decrypt_image will add .png
            &secret,
        )?;

        let decrypted_file_with_ext = decrypted_path_base.with_extension("png");
        assert!(decrypted_file_with_ext.exists(), "Decrypted PNG file should exist.");
        let decrypted_data_content = fs::read(&decrypted_file_with_ext)?;

        assert_eq!(original_data, decrypted_data_content, "Decrypted data should match original for steganographic PNG (no base).");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_png_with_base() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input_for_steg_base.dat");
        let base_image_path = temp_dir.path().join("base_carrier.png");
        let encrypted_path_base = temp_dir.path().join("test_encrypted_steg_w_base");
        let decrypted_path_base = temp_dir.path().join("test_decrypted_steg_w_base");

        // Create content to encrypt (can be anything, e.g., text data)
        let data_to_encrypt = b"Short payload for steganography with base image.";
        fs::write(&input_image_path, data_to_encrypt)?;
        
        // Create a small base PNG image
        create_dummy_png(&base_image_path, 20, 20)?; // Ensure it's large enough

        let secret = Zeroizing::new("passwordForStegWithBase123$%^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 1; // Use 1 LSB to match decryption logic assumption

        // Encrypt
        encrypt_image(
            &input_image_path,
            &encrypted_path_base, // .png will be added
            &secret,
            output_format_preference,
            Some(&base_image_path), // Provide base image
            lsb_bits,
        )?;

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file (with base) should exist.");

        // Decrypt
        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Extension will be determined by detect_file_format
            &secret,
        )?;
        
        // Since the original data was not a PNG, detect_file_format will return None,
        // so the decrypted file will be saved with the base name.
        assert!(decrypted_path_base.exists(), "Decrypted file (with base) should exist.");
        let decrypted_data_content = fs::read(&decrypted_path_base)?;

        assert_eq!(data_to_encrypt.to_vec(), decrypted_data_content, "Decrypted data should match original for steganographic PNG (with base).");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_validate_password_complexity_valid() {
        assert!(validate_password_complexity("ValidPass123!@#$")); // Changed: Added '$' to make length 16
        assert!(validate_password_complexity("Another_Good-Password456$"));
    }

    #[test]
    fn test_validate_password_complexity_too_short() {
        assert!(!validate_password_complexity("Short1!"));
    }

    #[test]
    fn test_validate_password_complexity_no_uppercase() {
        assert!(!validate_password_complexity("nouppercase123!@#"));
    }

    #[test]
    fn test_validate_password_complexity_no_lowercase() {
        assert!(!validate_password_complexity("NOLOWERCASE123!@#"));
    }

    #[test]
    fn test_validate_password_complexity_no_digit() {
        assert!(!validate_password_complexity("NoDigitPassword!@#"));
    }

    #[test]
    fn test_validate_password_complexity_no_symbol() {
        assert!(!validate_password_complexity("NoSymbolPassword123"));
    }

    #[test]
    fn test_validate_password_complexity_all_criteria_missing_sequentially() {
        // Too short
        assert!(!validate_password_complexity("Pass1!"));
        // Missing uppercase
        assert!(!validate_password_complexity("validpass123!@#"));
        // Missing lowercase
        assert!(!validate_password_complexity("VALIDPASS123!@#"));
        // Missing digit
        assert!(!validate_password_complexity("ValidPassword!@#"));
        // Missing symbol
        assert!(!validate_password_complexity("ValidPassword123"));
    }
}
