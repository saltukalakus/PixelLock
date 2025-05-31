use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::GenericImageView;
use std::{fs, path::{Path, PathBuf}}; // Added fs and Path here for process_folder_decryption
use argon2::password_hash::SaltString;
use zeroize::Zeroizing; // Added for process_folder_decryption
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::secret::{derive_encryption_key_with_salt}; 
use crate::encrypt::{SALT_STRING_LEN, NONCE_STRING_LEN};

/// Processes all supported files in an input directory for decryption.
pub fn process_folder_decryption(
    input_dir_str: &str,
    output_dir_str: &str,
    secret: &Zeroizing<String>,
) {
    let input_dir = Path::new(input_dir_str);
    let output_dir = Path::new(output_dir_str);

    if !output_dir.exists() {
        if let Err(e) = fs::create_dir_all(output_dir) {
            eprintln!("Error: Could not create output directory '{}': {}", output_dir_str, e);
            std::process::exit(1);
        }
        println!("Created output directory: {:?}", output_dir);
    } else if !output_dir.is_dir() {
        eprintln!("Error: Output path '{}' exists but is not a directory.", output_dir_str);
        std::process::exit(1);
    }

    match fs::read_dir(input_dir) {
        Ok(entries) => {
            let mut files_processed_successfully = 0;
            let mut files_failed_to_process = 0;
            let mut files_skipped_extension = 0;
            println!("\nStarting folder decryption...");

            for entry_result in entries {
                match entry_result {
                    Ok(entry) => {
                        let current_input_file_path = entry.path();
                        if current_input_file_path.is_file() {
                            let extension = current_input_file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
                            let lower_extension = extension.to_lowercase();

                            if !(lower_extension == "txt" || lower_extension == "png") {
                                files_skipped_extension += 1;
                                continue;
                            }

                            let stem = current_input_file_path.file_stem().unwrap_or_else(|| std::ffi::OsStr::new("decrypted_file"));
                            let current_output_file_path_base = output_dir.join(stem);

                            print!("Decrypting {:?} -> {:?} (extension auto-detected) ... ",
                                   current_input_file_path,
                                   current_output_file_path_base);

                            match decrypt_image(&current_input_file_path, &current_output_file_path_base, secret) { // Call local decrypt_image
                                Ok(_) => {
                                    println!("Done.");
                                    files_processed_successfully += 1;
                                }
                                Err(e) => {
                                    eprintln!("\nError decrypting file {:?}: {}", current_input_file_path, e);
                                    files_failed_to_process += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading a directory entry: {}", e);
                        files_failed_to_process += 1;
                    }
                }
            }
            println!("\nFolder decryption summary:");
            println!("  Files successfully decrypted: {}", files_processed_successfully);
            println!("  Files failed to decrypt: {}", files_failed_to_process);
            if files_skipped_extension > 0 {
                println!("  Files skipped (unsupported extension): {}", files_skipped_extension);
            }
        }
        Err(e) => {
            eprintln!("Error: Could not read input directory '{}': {}", input_dir_str, e);
            std::process::exit(1);
        }
    }
}

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
                    let current_extracted_bit = channel_value & data_extract_mask_header; // Extract the 0-th bit
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
                        } else if expected_total_payload_len_opt.is_some_and(|l| bits_processed_in_current_pixel_group >= l * 8) {
                            // Similar safeguard for payload bits.
                            // Transition/exit is handled by bytes_extracted_count for payload.
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
    use super::*; 
    use crate::encrypt::{SALT_STRING_LEN, NONCE_STRING_LEN}; // For constants
    use tempfile::tempdir;
    use std::fs;
    use image::{RgbImage, ImageFormat}; // For creating test PNGs
    use base64::{engine::general_purpose}; // For TXT test

    // Helper to create a dummy PNG with embedded data for testing extraction
    // This is a simplified embedding, primarily for testing extraction logic
    fn create_steganographic_png_for_test(
        path: &Path,
        lsb_config_for_payload: u8,
        payload_data: &[u8],
        image_width: u32,
        image_height: u32,
    ) -> Result<(), CryptoImageError> {
        let mut header_to_embed = vec![lsb_config_for_payload];
        header_to_embed.extend_from_slice(&(payload_data.len() as u32).to_be_bytes());

        let mut carrier_image = RgbImage::new(image_width, image_height);
        // Fill with some default pixels, e.g., black or random
        for pixel in carrier_image.pixels_mut() {
            *pixel = image::Rgb([0, 0, 0]);
        }

        let mut bit_idx_overall = 0;
        let mut current_data_source_byte_idx = 0;
        let mut current_data_source_bit_idx = 0;
        let mut embedding_header = true;

        let lsb_for_header: u8 = 1;

        'embedding_loop: for y in 0..image_height {
            for x in 0..image_width {
                let pixel = carrier_image.get_pixel_mut(x, y);
                for channel_idx in 0..3 {
                    let (_active_data_source, _active_lsb_bits, active_total_bits): (&[u8], u8, usize) = if embedding_header {
                        (header_to_embed.as_slice(), lsb_for_header, header_to_embed.len() * 8)
                    } else {
                        (payload_data, lsb_config_for_payload, payload_data.len() * 8)
                    };

                    if bit_idx_overall >= active_total_bits {
                        if embedding_header {
                            embedding_header = false;
                            bit_idx_overall = 0;
                            current_data_source_byte_idx = 0;
                            current_data_source_bit_idx = 0;
                            if active_total_bits == header_to_embed.len() * 8 && payload_data.is_empty() { // Header done, no payload
                                break 'embedding_loop;
                            }
                            // Re-evaluate active_data_source for the new stage (payload)
                            let (_new_data_source, _new_lsb_bits, new_total_bits) = 
                                (payload_data, lsb_config_for_payload, payload_data.len() * 8);
                            if bit_idx_overall >= new_total_bits { // Check if payload is already "done" (e.g. empty)
                                break 'embedding_loop;
                            }
                            // Continue with payload embedding in the same channel if space
                        } else { // Payload done
                            break 'embedding_loop;
                        }
                    }
                    
                    // Re-fetch active_data_source and its properties in case stage changed
                     let (current_active_data_source, current_active_lsb_bits, current_active_total_bits): (&[u8], u8, usize) = if embedding_header {
                        (header_to_embed.as_slice(), lsb_for_header, header_to_embed.len() * 8)
                    } else {
                        (payload_data, lsb_config_for_payload, payload_data.len() * 8)
                    };


                    let actual_clear_mask = if current_active_lsb_bits == 8 { 0x00 } else { 0xFF << current_active_lsb_bits };
                    
                    let mut bits_for_channel: u8 = 0;
                    for bit_k in 0..current_active_lsb_bits {
                        if bit_idx_overall < current_active_total_bits {
                            let data_byte = current_active_data_source[current_data_source_byte_idx];
                            let current_data_bit = (data_byte >> current_data_source_bit_idx) & 1;
                            bits_for_channel |= current_data_bit << bit_k;
                            
                            bit_idx_overall += 1;
                            current_data_source_bit_idx += 1;
                            if current_data_source_bit_idx == 8 {
                                current_data_source_bit_idx = 0;
                                current_data_source_byte_idx += 1;
                            }
                        } else { break; }
                    }
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & actual_clear_mask) | bits_for_channel;
                }
            }
        }
        carrier_image.save_with_format(path, ImageFormat::Png)?;
        Ok(())
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
    fn test_extract_payload_from_txt_valid() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let txt_path = temp_dir.path().join("test_payload.txt");
        let original_payload = b"This is a test payload for TXT.";
        let base64_payload = general_purpose::STANDARD.encode(original_payload);
        fs::write(&txt_path, base64_payload)?;

        let extracted_payload = extract_payload_from_carrier(&txt_path, "txt")?;
        assert_eq!(extracted_payload, original_payload.to_vec());
        Ok(())
    }

    #[test]
    fn test_extract_payload_from_png_valid() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let png_path = temp_dir.path().join("test_steg_payload.png");
        
        let salt_bytes = [1u8; SALT_STRING_LEN];
        let nonce_bytes = [2u8; NONCE_STRING_LEN];
        let ciphertext_bytes = b"dummy_ciphertext_data";
        let mut original_payload = Vec::new();
        original_payload.extend_from_slice(&salt_bytes);
        original_payload.extend_from_slice(&nonce_bytes);
        original_payload.extend_from_slice(ciphertext_bytes);

        let lsb_config: u8 = 2; // Use 2 LSBs for payload
        // Image size needs to be sufficient for header (5 bytes, 1 LSB) + payload (original_payload.len(), 2 LSBs)
        // Header: 5 bytes * 8 bits/byte / (3 channels * 1 bit/channel) = 40/3 = 14 pixels
        // Payload: original_payload.len() * 8 bits/byte / (3 channels * 2 bits/channel) 
        // Example: (22+12+21) * 8 / 6 = 55 * 8 / 6 = 440 / 6 = 74 pixels
        // Total pixels = 14 + 74 = 88 pixels. A 10x10 image (100 pixels) is enough.
        create_steganographic_png_for_test(&png_path, lsb_config, &original_payload, 10, 10)?;

        let extracted_payload = extract_payload_from_carrier(&png_path, "png")?;
        assert_eq!(extracted_payload, original_payload);
        Ok(())
    }

    #[test]
    fn test_extract_payload_png_header_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let png_path = temp_dir.path().join("test_steg_short_header.png");
        // Image 1x1 pixel can hold 3 bits for header (using 1 LSB). Header needs 5 bytes = 40 bits.
        create_steganographic_png_for_test(&png_path, 1, b"payload", 1, 1)?; 

        let result = extract_payload_from_carrier(&png_path, "png");
        assert!(matches!(result, Err(CryptoImageError::Steganography(msg)) if msg.contains("too small to extract full header")));
        Ok(())
    }

    #[test]
    fn test_extract_payload_png_invalid_lsb_config_in_header() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let png_path = temp_dir.path().join("test_steg_invalid_lsb.png");
        let invalid_lsb_config: u8 = 0; // Invalid LSB config
        // Create a PNG where the first byte of the header is `invalid_lsb_config`
        // Image needs to be large enough for the header (5 bytes, 1 LSB/channel) -> 14 pixels. 4x4=16 pixels.
        create_steganographic_png_for_test(&png_path, invalid_lsb_config, b"payload", 4, 4)?;

        let result = extract_payload_from_carrier(&png_path, "png");
        assert!(matches!(result, Err(CryptoImageError::Steganography(msg)) if msg.contains("Invalid LSB/embedding configuration")));
        Ok(())
    }

    #[test]
    fn test_extract_payload_png_payload_length_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let png_path = temp_dir.path().join("test_steg_payload_len_mismatch.png");

        // Create a header that claims a large payload, but image is too small for it
        let lsb_config: u8 = 1;
        let claimed_payload_len: u32 = 1000; // Large payload
        let _actual_payload_data = b"short"; // Actual data is short

        let mut header_to_embed = vec![lsb_config];
        header_to_embed.extend_from_slice(&claimed_payload_len.to_be_bytes());
        
        // Image size: 5x5 = 25 pixels.
        // Header needs 14 pixels. Remaining 11 pixels.
        // 11 pixels * 3 channels/pixel * 1 bit/channel = 33 bits = 4 bytes for payload.
        // This is less than `claimed_payload_len`.
        // We use the helper, but the helper will embed `actual_payload_data`.
        // The extraction logic should read the `claimed_payload_len` from the header.
        // The helper needs to be adjusted or a more manual PNG created for this specific case.
        // For now, let's test the scenario where the header is read correctly, but then extraction fails.
        // The current `create_steganographic_png_for_test` embeds the *actual* payload length.
        // To test this properly, we'd need to craft a PNG where the *embedded header* has a large length,
        // but the image itself is small.

        // Simplified: create an image that can hold the header, but not the claimed payload.
        // Header (5 bytes, 1 LSB/channel) -> 14 pixels.
        // Let's make an image of 5x3=15 pixels. It can hold the header.
        // If header says payload is 1000 bytes, it will fail.
        let mut carrier_image = RgbImage::new(5, 3); // 15 pixels
        for pixel in carrier_image.pixels_mut() { *pixel = image::Rgb([0,0,0]); }

        let mut _bit_idx_overall = 0;
        let mut current_data_source_byte_idx = 0;
        let mut current_data_source_bit_idx = 0;
        
        'header_embed_loop: for y in 0..3 { // 5x3 image
            for x in 0..5 {
                let pixel = carrier_image.get_pixel_mut(x,y);
                for channel_idx in 0..3 {
                    if current_data_source_byte_idx >= header_to_embed.len() { break 'header_embed_loop; }

                    let data_byte = header_to_embed[current_data_source_byte_idx];
                    let current_data_bit = (data_byte >> current_data_source_bit_idx) & 1;
                    
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & 0xFE) | current_data_bit; // Embed in LSB

                    _bit_idx_overall +=1;
                    current_data_source_bit_idx +=1;
                    if current_data_source_bit_idx == 8 {
                        current_data_source_bit_idx = 0;
                        current_data_source_byte_idx +=1;
                    }
                }
            }
        }
        carrier_image.save_with_format(&png_path, ImageFormat::Png)?;


        let result = extract_payload_from_carrier(&png_path, "png");
        // Expecting error because the image is too small for the payload length specified in its header
        assert!(matches!(result, Err(CryptoImageError::Steganography(ref msg)) if msg.contains("data incomplete") || msg.contains("too small")), "Result was: {:?}", result);

        Ok(())
    }
}
