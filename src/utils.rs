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

    let salt_bytes_to_store = salt.as_str().as_bytes(); // Changed from salt.as_bytes()
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

        let total_bits_to_embed = data_to_embed.len() * 8;
        let bits_per_pixel = 3 * lsb_bits_per_channel as usize;
        if bits_per_pixel == 0 {
            return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                image::error::ParameterErrorKind::Generic("LSB bits per channel cannot be zero.".to_string())
            )));
        }
        let pixels_needed = (total_bits_to_embed + bits_per_pixel - 1) / bits_per_pixel;

        let mut carrier_image: RgbImage;

        if let Some(base_path_ref) = base_image_path_opt {
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
                carrier_image = base_rgb_image;
            } else {
                let mut new_width = base_width;
                let mut new_height = base_height;
                while ((new_width * new_height) as usize) < pixels_needed {
                    new_width *= 2;
                    new_height *= 2; 
                }
                if new_width == 0 { new_width = (pixels_needed as f64).sqrt().ceil() as u32; }
                if new_height == 0 { new_height = (pixels_needed as u32 + new_width - 1) / new_width; }
                if new_width == 0 { new_width = 1; }
                if new_height == 0 { new_height = 1; }

                let mut tiled_image = RgbImage::new(new_width, new_height);
                if base_width > 0 && base_height > 0 {
                    for y_tiled in 0..new_height {
                        for x_tiled in 0..new_width {
                            let orig_x = x_tiled % base_width;
                            let orig_y = y_tiled % base_height;
                            tiled_image.put_pixel(x_tiled, y_tiled, *base_rgb_image.get_pixel(orig_x, orig_y));
                        }
                    }
                } else {
                    for pixel in tiled_image.pixels_mut() {
                        *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
                    }
                }
                carrier_image = tiled_image;
            }
        } else {
            let width = (pixels_needed as f64).sqrt().ceil() as u32;
            let mut height = (pixels_needed as u32 + width - 1) / width;
            if width == 0 { return Err(ImageError::Parameter(image::error::ParameterError::from_kind(image::error::ParameterErrorKind::Generic("Calculated width is zero for new image".into())))); }
            if height == 0 { height = 1; }

            carrier_image = RgbImage::new(width, height);
            for pixel_val in carrier_image.pixels_mut() {
                *pixel_val = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
            }
        }
        
        let mut bit_idx_overall = 0; 
        let (img_width, img_height) = carrier_image.dimensions();
        
        let clear_mask: u8 = 0xFF << lsb_bits_per_channel;
        let data_extract_mask: u8 = (1 << lsb_bits_per_channel) - 1;

        'embedding_loop: for y in 0..img_height {
            for x in 0..img_width {
                if bit_idx_overall >= total_bits_to_embed {
                    break 'embedding_loop;
                }
                let pixel = carrier_image.get_pixel_mut(x, y);
                
                for channel_idx in 0..3 {
                    if bit_idx_overall >= total_bits_to_embed {
                        break 'embedding_loop;
                    }
                    
                    let mut bits_for_channel: u8 = 0;
                    for bit_k in 0..lsb_bits_per_channel {
                        if bit_idx_overall < total_bits_to_embed {
                            let data_byte_idx = bit_idx_overall / 8;
                            let bit_in_byte_idx = bit_idx_overall % 8;
                            let current_data_bit = (data_to_embed[data_byte_idx] >> bit_in_byte_idx) & 1;
                            bits_for_channel |= current_data_bit << bit_k;
                            bit_idx_overall += 1;
                        } else {
                            break; 
                        }
                    }
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & clear_mask) | (bits_for_channel & data_extract_mask);
                }
            }
        }
        
        if bit_idx_overall < total_bits_to_embed {
            return Err(ImageError::Parameter(image::error::ParameterError::from_kind(
                image::error::ParameterErrorKind::Generic("Carrier image too small to embed all data bits.".to_string())
            )));
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

pub fn decrypt_image<PIn: AsRef<Path> + std::fmt::Debug, POut: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: PIn,
    output_decrypted_path_base: POut,
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
        
        let lsb_bits_per_channel_decrypt: u8 = 1; 
        let data_extract_mask_decrypt: u8 = (1 << lsb_bits_per_channel_decrypt) - 1;

        let mut extracted_all_bytes = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        
        let mut payload_len_opt: Option<usize> = None;
        let mut bytes_extracted_count = 0;

        let theoretical_max_bytes = (width as usize * height as usize * 3) / 8;

        'extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0;

                for channel_idx in 0..3 {
                    let extracted_bits_from_channel = pixel_channels[channel_idx] & data_extract_mask_decrypt; 
                    
                    for bit_k in 0..lsb_bits_per_channel_decrypt {
                        let current_extracted_bit = (extracted_bits_from_channel >> bit_k) & 1;
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            extracted_all_bytes.push(current_reconstructed_byte);
                            bytes_extracted_count += 1;
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if bytes_extracted_count == 4 && payload_len_opt.is_none() {
                                let len_arr: [u8; 4] = extracted_all_bytes[0..4].try_into().map_err(|_| 
                                    ImageError::Decoding(image::error::DecodingError::new(
                                        image::error::ImageFormatHint::Exact(ImageFormat::Png),
                                        "Failed to convert extracted length bytes to array".to_string(),
                                )))?;
                                payload_len_opt = Some(u32::from_be_bytes(len_arr) as usize);
                            }

                            if let Some(len) = payload_len_opt {
                                if bytes_extracted_count >= 4 + len {
                                    break 'extraction_loop;
                                }
                            }
                            
                            if bytes_extracted_count > theoretical_max_bytes + 4 {
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
        encrypted_file_data_payload = extracted_all_bytes[4..4 + payload_len].to_vec();
        println!("Decrypting from Steganography PNG file (LSB): {:?}", input_encrypted_path);
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
    let salt = SaltString::from_b64(salt_str).map_err(|e| ImageError::Decoding(image::error::DecodingError::new( // Changed from SaltString::new
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
