use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::GenericImageView;
use std::{fs, path::{Path, PathBuf}};
use argon2::password_hash::SaltString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::utils::{derive_encryption_key_with_salt}; 
use crate::encrypt::{SALT_STRING_LEN, NONCE_STRING_LEN};

/// Extracts the raw encrypted data payload from the carrier file (either .txt or .png).
///
/// # Arguments
/// * `input_encrypted_path` - Path to the encrypted file.
/// * `input_extension` - The lowercased extension of the input file.
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the raw encrypted payload.
/// * `Err(CryptoImageError)` on failure.
fn extract_payload_from_carrier(
    input_encrypted_path: &Path,
    input_extension: &str,
) -> Result<Vec<u8>, CryptoImageError> {
    if input_extension == "txt" {
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?;
        let payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())?;
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
        Ok(payload)
    } else if input_extension == "png" {
        let carrier_image = image::open(input_encrypted_path)?;
        let (width, height) = carrier_image.dimensions();
        
        let mut extracted_bytes_buffer = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        let mut bytes_extracted_count = 0;

        let lsb_bits_for_header: u8 = 1;
        let data_extract_mask_header: u8 = (1 << lsb_bits_for_header) - 1;
        let header_len_bytes: usize = 5; // 1 byte for LSB config, 4 bytes for payload length
        
        println!("Attempting to extract steganography header ({} bytes using {} LSB/channel)...", header_len_bytes, lsb_bits_for_header);

        // First pass: Extract just the header to get LSB config and payload length
        'header_extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0;
                for &channel_value in pixel_channels.iter().take(3) { // Iterate over R, G, B channels
                    // Extract LSB_BITS_FOR_HEADER (1 bit) from the channel
                    // In this loop, we are always using lsb_bits_for_header (1)
                    let current_extracted_bit = (channel_value >> 0) & data_extract_mask_header; // Extract the 0-th bit
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

        if bytes_extracted_count < header_len_bytes {
            return Err(CryptoImageError::Steganography(
                format!("Steganography PNG too small to extract full header. Expected {} bytes, got {}.", header_len_bytes, bytes_extracted_count),
            ));
        }
        
        let lsb_bits_for_payload_from_header = extracted_bytes_buffer[0];
        if !((1..=4).contains(&lsb_bits_for_payload_from_header) || lsb_bits_for_payload_from_header == 8) {
            return Err(CryptoImageError::Steganography(
                format!("Invalid LSB/embedding configuration in steganography header: {} (must be 1-4 for LSB, or 8 for full-bit embedding).", lsb_bits_for_payload_from_header),
            ));
        }

        let payload_len_arr: [u8; 4] = extracted_bytes_buffer[1..5].try_into()
            .map_err(|_| CryptoImageError::Steganography("Failed to convert extracted payload length bytes.".to_string()))?;
        let actual_payload_len = u32::from_be_bytes(payload_len_arr) as usize;
        
        println!("Header extracted: LSBs for payload = {}, Payload length = {}. Attempting to extract payload...", lsb_bits_for_payload_from_header, actual_payload_len);

        // Reset for full payload extraction (including re-extracting header for simplicity of loop structure,
        // but now using the determined lsb_bits_for_payload for the payload part)
        let mut all_extracted_data_bytes = Vec::new();
        current_reconstructed_byte = 0;
        bits_in_current_byte = 0;
        bytes_extracted_count = 0; // Counts bytes of the final payload (salt+nonce+ciphertext)

        let mut lsb_config_for_payload_opt: Option<u8> = None;
        let mut expected_total_payload_len_opt: Option<usize> = None;
        let mut extracting_header_stage = true; // True while extracting the 5-byte header, false for main payload
        let mut bits_processed_in_current_pixel_group = 0; // Tracks bits for current header/payload stage

        'full_extraction_loop: for y_img in 0..height {
            for x_img in 0..width {
                let pixel_channels_val = carrier_image.get_pixel(x_img, y_img).0;
                for &channel_val_pix in pixel_channels_val.iter().take(3) { // R, G, B
                    let lsb_to_use_now = if extracting_header_stage {
                        lsb_bits_for_header // Always 1 for header
                    } else {
                        lsb_config_for_payload_opt.unwrap_or(1) // Should be set after header
                    };

                    for bit_k_idx in 0..lsb_to_use_now {
                        // Check if we have extracted enough bits for the current stage (header or payload)
                        if extracting_header_stage {
                            if bits_processed_in_current_pixel_group >= (header_len_bytes * 8) {
                                // This condition should ideally be caught by bytes_extracted_count check below
                                // but acts as a safeguard for bit-level counting.
                                // Transition to payload extraction is handled when header_len_bytes are formed.
                            }
                        } else {
                            if expected_total_payload_len_opt.is_some_and(|l| bits_processed_in_current_pixel_group >= l * 8) {
                                // Similar safeguard for payload bits.
                                // Transition/exit is handled by bytes_extracted_count for payload.
                            }
                        }


                        let current_extracted_bit = (channel_val_pix >> bit_k_idx) & 1;
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;
                        bits_processed_in_current_pixel_group +=1;

                        if bits_in_current_byte == 8 { // A full byte has been reconstructed
                            if extracting_header_stage {
                                all_extracted_data_bytes.push(current_reconstructed_byte); // Temp store header bytes
                            } else {
                                // This byte belongs to the main payload (salt+nonce+ciphertext)
                                // Check if we are still within the expected payload length
                                if expected_total_payload_len_opt.is_none() || bytes_extracted_count < expected_total_payload_len_opt.unwrap() {
                                     all_extracted_data_bytes.push(current_reconstructed_byte);
                                } else {
                                    // We've collected more bytes than expected for the payload, something is wrong or it's just padding.
                                    // For now, we assume the length in header is exact.
                                }
                            }
                            bytes_extracted_count += 1;
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if extracting_header_stage && bytes_extracted_count == header_len_bytes {
                                // Header fully extracted
                                let lsb_val = all_extracted_data_bytes[0];
                                if !((1..=4).contains(&lsb_val) || lsb_val == 8) {
                                     return Err(CryptoImageError::Steganography(
                                        format!("Invalid LSB/embedding config in header: {} (must be 1-4 or 8)", lsb_val)));
                                }
                                lsb_config_for_payload_opt = Some(lsb_val);

                                let len_arr_payload: [u8; 4] = all_extracted_data_bytes[1..5].try_into().unwrap();
                                expected_total_payload_len_opt = Some(u32::from_be_bytes(len_arr_payload) as usize);
                                
                                // println!("Steg Header Decoded: LSBs for payload: {}, Payload length: {}", lsb_val, expected_total_payload_len_opt.unwrap());

                                extracting_header_stage = false; // Switch to payload extraction mode
                                bytes_extracted_count = 0; // Reset byte counter for the main payload
                                all_extracted_data_bytes.clear(); // Clear header bytes, start collecting payload
                                bits_processed_in_current_pixel_group = 0; // Reset bit counter for payload stage


                                if expected_total_payload_len_opt.unwrap() == 0 { // No payload to extract
                                    break 'full_extraction_loop;
                                }
                            } else if !extracting_header_stage &&
                                      expected_total_payload_len_opt == Some(bytes_extracted_count)
                            { // Main payload fully extracted
                                break 'full_extraction_loop;
                            }
                        }
                    }
                    // Check after each channel if payload is complete (if not in header stage)
                    if !extracting_header_stage &&
                       expected_total_payload_len_opt.is_some_and(|len_val|
                           bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0) // Handles 0-length payload
                       )
                    {
                        break 'full_extraction_loop;
                    }
                }
                // Check after each pixel if payload is complete
                if !extracting_header_stage &&
                   expected_total_payload_len_opt.is_some_and(|len_val|
                       bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0)
                   )
                {
                    break 'full_extraction_loop;
                }
            }
        }

        if extracting_header_stage || lsb_config_for_payload_opt.is_none() || expected_total_payload_len_opt.is_none() {
            return Err(CryptoImageError::Steganography(
                "Failed to extract steganography header or determine payload parameters.".to_string(),
            ));
        }
        
        let final_payload_len = expected_total_payload_len_opt.unwrap();
        if all_extracted_data_bytes.len() < final_payload_len {
             return Err(CryptoImageError::Steganography(
                format!("Steganography PNG data incomplete. Expected {} payload bytes, extracted {}.", final_payload_len, all_extracted_data_bytes.len()),
            ));
        }
        
        // Trim to exact length if more bytes were collected due to pixel boundaries
        all_extracted_data_bytes.truncate(final_payload_len);

        println!("Decrypting from Steganography PNG file (LSB {}): {:?}", lsb_config_for_payload_opt.unwrap(), input_encrypted_path);
        Ok(all_extracted_data_bytes)

    } else {
        Err(CryptoImageError::InvalidParameter(
            format!("Unsupported input file type for decryption: .{}", input_extension)
        ))
    }
}

/// Detects common image file formats based on magic bytes.
///
/// # Arguments
/// * `decrypted_data` - A byte slice of the data to check.
///
/// # Returns
/// * `Some(&'static str)` containing the file extension (e.g., "jpeg", "png") if a known format is detected.
/// * `None` if the format is not recognized.
fn detect_file_format(decrypted_data: &[u8]) -> Option<&'static str> {
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

    // Extract the payload
    let encrypted_file_data_payload = extract_payload_from_carrier(input_encrypted_path, &input_extension)?;

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

#[cfg(test)]
mod tests {
    use super::*; // To bring detect_file_format into scope for tests

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
}
