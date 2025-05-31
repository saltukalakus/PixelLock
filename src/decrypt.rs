use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::GenericImageView;
use std::{fs, path::{Path, PathBuf}};
use argon2::password_hash::SaltString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::secret::{derive_encryption_key_with_salt}; 
use crate::encrypt::{SALT_STRING_LEN, NONCE_STRING_LEN, VERSION_INFO_LEN, EXT_LEN_FIELD_LEN};

/// Processes all supported files in an input directory for decryption.
pub fn process_folder_decryption(
    input_dir_str: &str,
    output_dir_str: &str,
    secret: &Zeroizing<String>,
    app_version: (u8, u8, u8),
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
                            // Skip hidden files (e.g., .DS_Store) robustly
                            if let Some(name_os_str) = current_input_file_path.file_name() {
                                if name_os_str.to_string_lossy().starts_with('.') {
                                    continue; // Silently skip hidden files
                                }
                            }

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

                            match decrypt_file(&current_input_file_path, &current_output_file_path_base, secret, app_version) { // Call local decrypt_file
                                Ok(_) => {
                                    println!("Done.");
                                    files_processed_successfully += 1;
                                }
                                Err(_e) => { // Marked 'e' as unused
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
    if input_extension == "txt" { // Removed parentheses
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?;
        let payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())?;
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
        Ok(payload)
    } else if input_extension == "png" { // Removed parentheses
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
    // --- BEGIN ADDED DEBUGGING ---
    let max_bytes_to_print = std::cmp::min(decrypted_data.len(), 32); // Print up to 32 bytes
    println!(
        "DEBUG detect_file_format: First {} bytes (hex): {:?}",
        max_bytes_to_print,
        &decrypted_data[..max_bytes_to_print]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ")
    );
    // --- END ADDED DEBUGGING ---

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
    } else if decrypted_data.starts_with(b"%PDF-") { // PDF
        Some("pdf")
    } else if decrypted_data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) || decrypted_data.starts_with(&[0x50, 0x4B, 0x05, 0x06]) || decrypted_data.starts_with(&[0x50, 0x4B, 0x07, 0x08]) { // ZIP (PK variants)
        // Further checks for DOCX, XLSX, PPTX (they are ZIP files)
        // This requires looking for specific file entries within the ZIP structure, which is complex.
        // For simplicity, we'll identify them as "zip" for now. A more robust solution would inspect ZIP contents.
        // A common approach for Office Open XML is to check for `[Content_Types].xml` or specific relationship parts.
        // For now, just "zip" is a good first step.
        Some("zip")
        // To distinguish docx/xlsx/pptx, one would need to parse the zip and look for specific file names.
        // Example (conceptual, not implemented here due to complexity):
        // if is_docx_structure(decrypted_data) { return Some("docx"); }
        // else if is_xlsx_structure(decrypted_data) { return Some("xlsx"); }
        // else if is_pptx_structure(decrypted_data) { return Some("pptx"); }
    } else if decrypted_data.starts_with(b"ID3") || (decrypted_data.len() > 1 && decrypted_data[0] == 0xFF && (decrypted_data[1] & 0xE0) == 0xE0) { // MP3 (ID3 tag or frame sync)
        Some("mp3")
    } else if decrypted_data.len() >= 12 && &decrypted_data[4..8] == b"ftyp" { // MP4 container and related (e.g. mov, m4a, m4v)
        // Common ftyp signatures: "isom", "mp41", "mp42", "m4v ", "m4a ", "mov "
        // For simplicity, we'll broadly classify as "mp4" if "ftyp" is present at offset 4.
        Some("mp4")
    } else if decrypted_data.starts_with(b"RIFF") && decrypted_data.len() >= 12 && &decrypted_data[8..12] == b"WAVE" { // WAV
        Some("wav")
    } else if decrypted_data.starts_with(&[0x1F, 0x8B]) { // GZIP
        Some("gz")
    } else if decrypted_data.len() >= 262 && &decrypted_data[257..262] == b"ustar" { // TAR
        Some("tar")
    } else if decrypted_data.starts_with(b"{\\rtf") { // RTF
        Some("rtf")
    } else if decrypted_data.starts_with(b"fLaC") { // FLAC native
        Some("flac")
    } else if decrypted_data.starts_with(b"OggS") { // OGG
        Some("ogg")
    } else {
        None
    }
}

/// Decrypts an image file that was previously encrypted by `encrypt_image`.
/// It handles both Base64 encoded text files and steganographic PNG files.
///
/// # Arguments
/// * `input_encrypted_path_ref` - Path to the encrypted file (.txt or .png).
/// * `output_decrypted_path_base` - Base path for the output decrypted file. The extension will be auto-detected or taken from payload.
/// * `secret` - The user-provided secret (password) for decryption.
/// * `current_app_version` - The version tuple (major, minor, patch) of the currently running application.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(CryptoImageError)` on failure.
pub fn decrypt_file<PIn: AsRef<Path> + std::fmt::Debug, POut: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: PIn,
    output_decrypted_path_base: POut,
    secret: &Zeroizing<String>,
    current_app_version: (u8, u8, u8),
) -> Result<(), CryptoImageError> {
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload = extract_payload_from_carrier(input_encrypted_path, &input_extension)?;

    // Check minimum length: Version (3) + Salt (22) + ExtLen (1) + Nonce (12)
    // Extension itself can be 0 length.
    let min_payload_len = VERSION_INFO_LEN + SALT_STRING_LEN + EXT_LEN_FIELD_LEN + NONCE_STRING_LEN;
    if encrypted_file_data_payload.len() < min_payload_len {
        return Err(CryptoImageError::Decryption(format!(
            "Extracted encrypted data is too short. Expected at least {} bytes, got {}.",
            min_payload_len,
            encrypted_file_data_payload.len()
        )));
    }

    let (version_bytes, rest_after_version) = encrypted_file_data_payload.split_at(VERSION_INFO_LEN);
    let stored_version = (version_bytes[0], version_bytes[1], version_bytes[2]);

    // Optional: Log or compare versions
    if stored_version.0 != current_app_version.0 {
        // ANSI escape codes for red text
        const RED: &str = "\x1b[31m";
        const RESET: &str = "\x1b[0m";
        let error_message = format!(
            "{}Critical version mismatch: File encrypted with major version {}, current app major version is {}. Decryption aborted.{}",
            RED,
            stored_version.0,
            current_app_version.0,
            RESET
        );
        eprintln!("{}", error_message); // Print to stderr for visibility
        return Err(CryptoImageError::Decryption(format!(
            "File encrypted with major version {}, current app major version is {}. Cannot decrypt due to major version incompatibility.",
            stored_version.0,
            current_app_version.0
        )));
    } else if stored_version == current_app_version {
        println!(
            "File encrypted with version: {}.{}.{}. Current app version: {}.{}.{}",
            stored_version.0, stored_version.1, stored_version.2,
            current_app_version.0, current_app_version.1, current_app_version.2
        );
    } else {
        // ANSI escape codes for red text
        const RED: &str = "\x1b[31m";
        const RESET: &str = "\x1b[0m";
        println!(
            "{}File encrypted with version: {}.{}.{}. Current app version: {}.{}.{}. Version mismatch.{}",
            RED,
            stored_version.0, stored_version.1, stored_version.2,
            current_app_version.0, current_app_version.1, current_app_version.2,
            RESET
        );
    }

    let (salt_string_bytes, rest_after_salt) = rest_after_version.split_at(SALT_STRING_LEN);
    
    // Extract ExtLen and Extension
    let (ext_len_byte_slice, rest_after_ext_len) = rest_after_salt.split_at(EXT_LEN_FIELD_LEN);
    let ext_len = ext_len_byte_slice[0] as usize;

    if rest_after_ext_len.len() < ext_len + NONCE_STRING_LEN {
        return Err(CryptoImageError::Decryption(format!(
            "Encrypted data too short to contain extension (len {}) and nonce (len {}). Remaining: {}",
            ext_len, NONCE_STRING_LEN, rest_after_ext_len.len()
        )));
    }
    let (extension_bytes, rest_after_extension) = rest_after_ext_len.split_at(ext_len);
    let stored_extension_str = std::str::from_utf8(extension_bytes)?;


    let (nonce_bytes, ciphertext) = rest_after_extension.split_at(NONCE_STRING_LEN);

    let salt_str = std::str::from_utf8(salt_string_bytes)?;
    let salt = SaltString::from_b64(salt_str)?;

    let derived_key = derive_encryption_key_with_salt(secret, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoImageError::Decryption("AEAD decryption failed (possibly wrong secret or corrupted file)".to_string()))?;
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());
    let mut final_output_path = output_decrypted_path_base_buf.clone(); // Default to base path

    if let Some(detected_format) = detect_file_format(&decrypted_data) {
        if detected_format == "zip" {
            // If detected as zip, check if stored extension is a more specific known office format
            match stored_extension_str.to_lowercase().as_str() {
                "ods" | "xlsx" | "docx" | "pptx" => {
                    final_output_path = output_decrypted_path_base_buf.with_extension(stored_extension_str);
                    println!("Detected as ZIP, but using stored specific extension: {:?}. Saving decrypted file to: {:?}", stored_extension_str, final_output_path);
                }
                _ => {
                    // It's a generic zip or some other zip-based format we don't specifically handle, so use "zip"
                    final_output_path = output_decrypted_path_base_buf.with_extension(detected_format);
                    println!("Detected file format: {:?}. Saving decrypted file to: {:?}", detected_format, final_output_path);
                }
            }
        } else {
            // Detected format is not "zip", so use it directly
            final_output_path = output_decrypted_path_base_buf.with_extension(detected_format);
            println!("Detected file format: {:?}. Saving decrypted file to: {:?}", detected_format, final_output_path);
        }
    } else if ext_len > 0 && !stored_extension_str.is_empty() {
        final_output_path = output_decrypted_path_base_buf.with_extension(stored_extension_str);
        println!("Used stored file extension: {:?}. Saving decrypted file to: {:?}", stored_extension_str, final_output_path);
    } else {
        eprintln!("Warning: Could not detect file format and no extension was stored. Saving decrypted data as is to: {:?}", final_output_path);
        // final_output_path remains the base path (no extension)
    }
    
    fs::write(&final_output_path, decrypted_data)?;

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
    fn test_detect_file_format_extended() {
        assert_eq!(detect_file_format(b"%PDF-1.4"), Some("pdf"));
        assert_eq!(detect_file_format(&[0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00]), Some("zip")); // ZIP PK0304
        assert_eq!(detect_file_format(b"ID3\x03\x00..."), Some("mp3")); // MP3 with ID3
        assert_eq!(detect_file_format(&[0xFF, 0xFB, 0x90, 0x44, 0x00]), Some("mp3")); // MP3 frame sync
        assert_eq!(detect_file_format(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"), Some("mp4")); // MP4
        assert_eq!(detect_file_format(b"RIFF\x00\x00\x00\x00WAVEfmt "), Some("wav")); // WAV
        assert_eq!(detect_file_format(&[0x1F, 0x8B, 0x08, 0x00]), Some("gz")); // GZIP
        let mut tar_data = vec![0u8; 512]; // TAR header is 512 bytes
        tar_data[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_file_format(&tar_data), Some("tar"));
        assert_eq!(detect_file_format(b"{\\rtf1\\ansi...}"), Some("rtf"));
        assert_eq!(detect_file_format(b"fLaC\x00\x00\x00\x22"), Some("flac")); // Native FLAC
        assert_eq!(detect_file_format(b"OggS\x00\x02"), Some("ogg"));
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
        
        // Payload now includes ExtLen and Extension
        let original_ext = "dat";
        let ext_len_byte = original_ext.len() as u8;
        let ext_bytes = original_ext.as_bytes();

        let salt_bytes = [1u8; SALT_STRING_LEN];
        let nonce_bytes = [2u8; NONCE_STRING_LEN];
        let ciphertext_bytes = b"dummy_ciphertext_data";
        
        let mut original_payload_content = Vec::new(); // This is what's after Version, Salt, ExtLen, Ext, Nonce
        original_payload_content.extend_from_slice(&salt_bytes);
        original_payload_content.push(ext_len_byte);
        original_payload_content.extend_from_slice(ext_bytes);
        original_payload_content.extend_from_slice(&nonce_bytes);
        original_payload_content.extend_from_slice(ciphertext_bytes);


        let lsb_config: u8 = 2; 
        // Recalculate pixels needed:
        // Header: 5 bytes (1 LSB/ch) -> 14 pixels
        // Payload: (22 salt + 1 ext_len + 3 ext + 12 nonce + 21 cipher) = 59 bytes
        // Payload bits: 59 * 8 = 472 bits. Pixels for payload (2 LSB/ch): ceil(472 / (3*2)) = ceil(472/6) = 79 pixels
        // Total pixels = 14 + 79 = 93 pixels. A 10x10 image (100 pixels) is enough.
        create_steganographic_png_for_test(&png_path, lsb_config, &original_payload_content, 10, 10)?;

        let extracted_payload = extract_payload_from_carrier(&png_path, "png")?;
        assert_eq!(extracted_payload, original_payload_content);
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

        // Image needs to be large enough for the header (5 bytes, 1 LSB/channel) -> 14 pixels.
        // Header (5 bytes, 1 LSB/channel) -> 14 pixels.
        // Make an image of 5x3=15 pixels. It can hold the header.
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
