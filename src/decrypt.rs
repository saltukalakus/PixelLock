use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::GenericImageView;
use std::{fs, path::{Path, PathBuf}};
use argon2::password_hash::SaltString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::utils::{SALT_STRING_LEN, NONCE_STRING_LEN, derive_encryption_key_with_salt, detect_file_format};

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
) -> Result<(), CryptoImageError> {
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload: Vec<u8>;

    if input_extension == "txt" {
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?;
        encrypted_file_data_payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())?;
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
    } else if input_extension == "png" {
        let carrier_image = image::open(input_encrypted_path)?;
        let (width, height) = carrier_image.dimensions();
        
        let mut extracted_bytes_buffer = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        let mut bytes_extracted_count = 0;

        let lsb_bits_for_header: u8 = 1;
        let data_extract_mask_header: u8 = (1 << lsb_bits_for_header) - 1;
        let header_len_bytes: usize = 5;
        
        println!("Attempting to extract steganography header ({} bytes using {} LSB/channel)...", header_len_bytes, lsb_bits_for_header);

        'header_extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0;
                for &channel_value in pixel_channels.iter().take(3) {
                    for bit_k in 0..lsb_bits_for_header {
                        let current_extracted_bit = (channel_value >> bit_k) & data_extract_mask_header;
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
                    }
                    if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
                }
                 if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
            }
             if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
        }

        if bytes_extracted_count < header_len_bytes {
            return Err(CryptoImageError::Steganography(
                format!("Steganography PNG too small to extract full header. Expected {} bytes, got {}.", header_len_bytes, bytes_extracted_count),
            ));
        }
        
        let lsb_bits_for_payload = extracted_bytes_buffer[0];
        if !(1..=4).contains(&lsb_bits_for_payload) {
            return Err(CryptoImageError::Steganography(
                format!("Invalid LSB configuration in steganography header: {} (must be 1-4).", lsb_bits_for_payload),
            ));
        }

        let payload_len_arr: [u8; 4] = extracted_bytes_buffer[1..5].try_into()
            .map_err(|_| CryptoImageError::Steganography("Failed to convert extracted payload length bytes.".to_string()))?;
        let payload_len = u32::from_be_bytes(payload_len_arr) as usize;
        
        println!("Header extracted: LSBs for payload = {}, Payload length = {}. Attempting to extract payload...", lsb_bits_for_payload, payload_len);

        let mut all_extracted_data_bytes = Vec::new();
        current_reconstructed_byte = 0;
        bits_in_current_byte = 0;
        bytes_extracted_count = 0;

        let mut lsb_config_for_payload_opt: Option<u8> = None;
        let mut actual_payload_len_opt: Option<usize> = None;
        let mut extracting_header_stage = true;
        
        'full_extraction_loop: for y_img in 0..height {
            for x_img in 0..width {
                let pixel_channels_val = carrier_image.get_pixel(x_img, y_img).0;
                for &channel_val_pix in pixel_channels_val.iter().take(3) {
                    let lsb_to_use_now = if extracting_header_stage {
                        lsb_bits_for_header
                    } else {
                        lsb_config_for_payload_opt.unwrap_or(1)
                    };

                    for bit_k_idx in 0..lsb_to_use_now {
                        let current_extracted_bit = (channel_val_pix >> bit_k_idx) & 1;
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            all_extracted_data_bytes.push(current_reconstructed_byte);
                            bytes_extracted_count += 1;
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if extracting_header_stage && bytes_extracted_count == header_len_bytes {
                                let lsb_val = all_extracted_data_bytes[0];
                                if !(1..=4).contains(&lsb_val) {
                                     return Err(CryptoImageError::Steganography(
                                        format!("Invalid LSB config in header: {}", lsb_val)));
                                }
                                lsb_config_for_payload_opt = Some(lsb_val);

                                let len_arr_payload: [u8; 4] = all_extracted_data_bytes[1..5].try_into().unwrap();
                                actual_payload_len_opt = Some(u32::from_be_bytes(len_arr_payload) as usize);
                                
                                println!("Steg Header Decoded: LSBs for payload: {}, Payload length: {}", lsb_val, actual_payload_len_opt.unwrap());

                                extracting_header_stage = false;
                                bytes_extracted_count = 0;
                                all_extracted_data_bytes.clear();

                                if actual_payload_len_opt.unwrap() == 0 {
                                    break 'full_extraction_loop;
                                }
                            } else if !extracting_header_stage &&
                                      actual_payload_len_opt == Some(bytes_extracted_count)
                            {
                                break 'full_extraction_loop;
                            }
                        }
                    }
                    if !extracting_header_stage &&
                       actual_payload_len_opt.is_some_and(|len_val|
                           bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0)
                       )
                    {
                        break 'full_extraction_loop;
                    }
                }
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
            return Err(CryptoImageError::Steganography(
                "Failed to extract steganography header or determine payload parameters.".to_string(),
            ));
        }
        
        let final_payload_len = actual_payload_len_opt.unwrap();
        if all_extracted_data_bytes.len() < final_payload_len {
             return Err(CryptoImageError::Steganography(
                format!("Steganography PNG data incomplete. Expected {} payload bytes, extracted {}.", final_payload_len, all_extracted_data_bytes.len()),
            ));
        }
        
        encrypted_file_data_payload = all_extracted_data_bytes;
        println!("Decrypting from Steganography PNG file (LSB {}): {:?}", lsb_config_for_payload_opt.unwrap(), input_encrypted_path);

    } else {
        return Err(CryptoImageError::InvalidParameter(
            format!("Unsupported input file type for decryption: .{}", input_extension)
        ));
    }

    if encrypted_file_data_payload.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(CryptoImageError::Decryption("Extracted encrypted data is too short".to_string()));
    }
    let (salt_string_bytes, rest) = encrypted_file_data_payload.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    let salt_str = std::str::from_utf8(salt_string_bytes)?;
    let salt = SaltString::from_b64(salt_str)?;

    let derived_key = derive_encryption_key_with_salt(secret, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoImageError::Decryption("AEAD decryption failed (possibly wrong secret or corrupted file)".to_string()))?;
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());

    if let Some(format) = detect_file_format(&decrypted_data) {
        let final_output_path = output_decrypted_path_base_buf.with_extension(format);
        println!("Detected file format: {:?}. Saving decrypted file to: {:?}", format, final_output_path);
        fs::write(&final_output_path, decrypted_data)?;
    } else {
        eprintln!("Warning: Could not detect file format. Saving decrypted data as is to: {:?}", output_decrypted_path_base_buf);
        fs::write(&output_decrypted_path_base_buf, decrypted_data)?;
    }

    Ok(())
}
