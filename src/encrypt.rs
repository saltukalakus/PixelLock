use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::{RgbImage};
use rand::{rngs::OsRng, Rng, random};
use std::{fs, path::{Path, PathBuf}}; // fs and Path are used by process_folder_encryption
use argon2::password_hash::SaltString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::secret::{derive_encryption_key_with_salt}; 

// Define constants here
pub const VERSION_INFO_LEN: usize = 3; // Major, Minor, Patch
pub const SALT_STRING_LEN: usize = 22;
pub const NONCE_STRING_LEN: usize = 12; 
pub const EXT_LEN_FIELD_LEN: usize = 1; // Length of the extension string's length field

/// Configuration for the core encryption logic.
pub struct EncryptionCoreConfig<'a, P: AsRef<Path> + std::fmt::Debug> {
    output_format_preference: &'a str,
    base_image_path_opt: Option<P>,
    lsb_bits_per_channel: u8,
    app_version: (u8, u8, u8),
}

/// Prepares or creates a carrier RgbImage for steganography.
///
/// If a base_image_path is provided, it attempts to use that image. If the base image is too small,
/// it's tiled to fit the required number of pixels.
/// If no base_image_path is provided, a new RgbImage is generated with random pixels,
/// sized to accommodate the required number of pixels.
///
/// # Arguments
/// * `base_image_path_opt` - Optional path to a base PNG image.
/// * `pixels_needed` - The total number of pixels required for the carrier image.
///
/// # Returns
/// * `Ok(RgbImage)` containing the prepared carrier image.
/// * `Err(CryptoImageError)` on failure (e.g., base image not found, not a PNG, or I/O errors).
fn prepare_carrier_image<P: AsRef<Path> + std::fmt::Debug>(
    base_image_path_opt: Option<P>,
    pixels_needed: usize,
) -> Result<RgbImage, CryptoImageError> {
    if let Some(base_path_ref) = base_image_path_opt {
        let base_path = base_path_ref.as_ref();
        if !base_path.exists() {
            return Err(CryptoImageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Base image not found: {:?}", base_path),
            )));
        }
        if base_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() != "png" {
            return Err(CryptoImageError::InvalidParameter("Base image must be a PNG file.".to_string()));
        }

        let base_dyn_image = image::open(base_path)?;
        let base_rgb_image = base_dyn_image.to_rgb8();
        let base_width = base_rgb_image.width();
        let base_height = base_rgb_image.height();
        let base_pixels_capacity = (base_width * base_height) as usize;

        if base_pixels_capacity >= pixels_needed {
            Ok(base_rgb_image)
        } else { // base_pixels_capacity < pixels_needed, need to tile or create larger
            let final_tiled_width: u32;
            let final_tiled_height: u32;

            if base_width == 0 || base_height == 0 {
                // Base image is 0x0 or invalid, treat as generating a new image for sizing
                let mut calc_width = (pixels_needed as f64).sqrt().ceil() as u32;
                calc_width = calc_width.max(1); // Ensure at least 1
                let mut calc_height = (pixels_needed as u32).div_ceil(calc_width);
                calc_height = calc_height.max(1); // Ensure at least 1
                final_tiled_width = calc_width;
                final_tiled_height = calc_height;
            } else {
                // Base image has dimensions, calculate tiles needed more precisely
                let mut num_tiles_x = 1u32;
                let mut num_tiles_y = 1u32;
                // Loop until capacity is sufficient
                while ((base_width * num_tiles_x * base_height * num_tiles_y) as usize) < pixels_needed {
                    // Alternate growing width and height tiles, prioritizing the smaller current tiled dimension
                    if base_width * num_tiles_x <= base_height * num_tiles_y {
                        num_tiles_x += 1;
                    } else {
                        num_tiles_y += 1;
                    }
                }
                final_tiled_width = base_width * num_tiles_x;
                final_tiled_height = base_height * num_tiles_y;
            }
            
            let mut tiled_image = RgbImage::new(final_tiled_width, final_tiled_height);
            if base_width > 0 && base_height > 0 {
                // Tile the original base image content
                for y_tiled in 0..final_tiled_height {
                    for x_tiled in 0..final_tiled_width {
                        let orig_x = x_tiled % base_width;
                        let orig_y = y_tiled % base_height;
                        tiled_image.put_pixel(x_tiled, y_tiled, *base_rgb_image.get_pixel(orig_x, orig_y));
                    }
                }
            } else {
                // Base image was 0x0, fill the new image with random pixels
                for pixel in tiled_image.pixels_mut() {
                    *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
                }
            }
            Ok(tiled_image)
        }
    } else {
        // No base image provided, generate a new one.
        let mut width = (pixels_needed as f64).sqrt().ceil() as u32;
        width = width.max(1); // Ensure at least 1x1
        let mut height = (pixels_needed as u32).div_ceil(width);
        height = height.max(1); // Ensure at least 1x1

        let mut new_image = RgbImage::new(width, height);
        for pixel_val in new_image.pixels_mut() {
            *pixel_val = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
        }
        Ok(new_image)
    }
}

/// Core encryption logic using a pre-derived key and salt.
/// This function is intended for use when the key and salt are managed externally (e.g., folder mode).
pub fn encrypt_file_core<P1, P2, P3>(
    input_image_path: P1,
    output_encrypted_path_param: P2,
    derived_key: &[u8; 32], // Accepts pre-derived key
    salt_for_payload: &SaltString, // Accepts salt used for derivation, to be stored
    config: &EncryptionCoreConfig<P3>,
) -> Result<String, CryptoImageError>
where
    P1: AsRef<Path> + std::fmt::Debug,
    P2: AsRef<Path> + std::fmt::Debug,
    P3: AsRef<Path> + std::fmt::Debug,
{
    let original_extension_str = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("") // Default to empty string if no extension
        .to_lowercase();

    let img_bytes = fs::read(&input_image_path)?;

    // Key derivation is skipped here; uses provided derived_key and salt_for_payload

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(derived_key));
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data_core = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| CryptoImageError::Encryption("AEAD encryption failed".to_string()))?;

    let salt_bytes_to_store = salt_for_payload.as_str().as_bytes(); 
    assert_eq!(salt_bytes_to_store.len(), SALT_STRING_LEN, "Provided salt string length does not match expected SALT_STRING_LEN.");

    let mut extension_bytes_to_store = original_extension_str.as_bytes().to_vec();
    if extension_bytes_to_store.len() > 255 { // Max length for a u8 field
        // Truncate or handle error - for now, truncate and log warning
        eprintln!("Warning: Original file extension longer than 255 bytes, truncating: {}", original_extension_str);
        extension_bytes_to_store.truncate(255);
    }
    let ext_len_byte = extension_bytes_to_store.len() as u8;

    let mut raw_output_payload = Vec::new();
    raw_output_payload.push(config.app_version.0); // Major
    raw_output_payload.push(config.app_version.1); // Minor
    raw_output_payload.push(config.app_version.2); // Patch
    raw_output_payload.extend_from_slice(salt_bytes_to_store);
    raw_output_payload.push(ext_len_byte); // Store length of the extension
    raw_output_payload.extend_from_slice(&extension_bytes_to_store); // Store the extension itself
    raw_output_payload.extend_from_slice(&nonce_bytes);
    raw_output_payload.extend_from_slice(&encrypted_data_core);
    
    let output_path_base = PathBuf::from(output_encrypted_path_param.as_ref());

    if config.output_format_preference == "txt" {
        let base64_encoded_data = general_purpose::STANDARD.encode(&raw_output_payload);
        let final_output_path = output_path_base.with_extension("txt");
        fs::write(&final_output_path, base64_encoded_data)?;
        println!("Image encrypted successfully to (Base64 TXT): {:?}", final_output_path);
    } else if config.output_format_preference == "png" {
        let lsb_config_byte = config.lsb_bits_per_channel; 
        let payload_len_bytes = (raw_output_payload.len() as u32).to_be_bytes();

        let mut header_to_embed = vec![lsb_config_byte];
        header_to_embed.extend_from_slice(&payload_len_bytes);

        let total_header_bits = header_to_embed.len() * 8;
        let total_payload_bits = raw_output_payload.len() * 8;

        let lsb_for_header: u8 = 1;
        let bits_per_pixel_header = 3 * lsb_for_header as usize;
        let bits_per_pixel_payload = 3 * config.lsb_bits_per_channel as usize;

        if bits_per_pixel_payload == 0 {
            return Err(CryptoImageError::InvalidParameter("LSB bits per channel for payload cannot be zero.".to_string()));
        }

        let pixels_needed_for_header = total_header_bits.div_ceil(bits_per_pixel_header);
        let pixels_needed_for_payload = total_payload_bits.div_ceil(bits_per_pixel_payload);
        let pixels_needed = pixels_needed_for_header + pixels_needed_for_payload;

        // Prepare or create the carrier image using the helper function.
        // Pass Option<&P3> by using .as_ref() to avoid moving from behind a shared reference.
        let mut carrier_image = prepare_carrier_image(config.base_image_path_opt.as_ref(), pixels_needed)?;
        
        let (img_width, img_height) = carrier_image.dimensions();
        
        // Calculate current capacity for clarity and to help the parser.
        let current_carrier_capacity = (img_width as usize) * (img_height as usize);

        // Ensure the prepared carrier image is actually large enough.
        // This is a safeguard, as prepare_carrier_image should handle sizing.
        if current_carrier_capacity < pixels_needed {
            return Err(CryptoImageError::Steganography(
                format!("Prepared carrier image is too small. Needed {} pixels, got {}x{} ({} pixels).", 
                        pixels_needed, img_width, img_height, current_carrier_capacity) // Use the new variable here
            ));
        }

        let mut bit_idx_overall = 0;
        let mut current_data_source_byte_idx = 0;
        let mut current_data_source_bit_idx = 0;
        let mut embedding_header = true;

        'embedding_loop: for y in 0..img_height {
            for x in 0..img_width {
                let pixel = carrier_image.get_pixel_mut(x, y);
                
                for channel_idx in 0..3 {
                    let total_bits_for_current_stage = if embedding_header { total_header_bits } else { total_payload_bits };
                    if bit_idx_overall >= total_bits_for_current_stage {
                        if embedding_header {
                            embedding_header = false;
                            bit_idx_overall = 0;
                            current_data_source_byte_idx = 0;
                            current_data_source_bit_idx = 0;
                            if total_payload_bits == 0 { break 'embedding_loop; }
                        } else {
                            break 'embedding_loop;
                        }
                    }
                    
                    let (active_data_source, active_lsb_bits, active_total_bits) = if embedding_header {
                        (&header_to_embed, lsb_for_header, total_header_bits)
                    } else {
                        (&raw_output_payload, config.lsb_bits_per_channel, total_payload_bits)
                    };

                    if bit_idx_overall >= active_total_bits { 
                         if embedding_header { 
                             embedding_header = false; 
                             bit_idx_overall = 0; 
                             current_data_source_byte_idx = 0;
                             current_data_source_bit_idx = 0;
                             if total_payload_bits == 0 { break 'embedding_loop; }
                             continue; 
                         } else {
                             break 'embedding_loop;
                         }
                    }

                    // Corrected mask calculation for active_lsb_bits potentially being 8
                    let actual_clear_mask: u8;
                    let actual_data_extract_mask: u8;

                    if active_lsb_bits == 8 {
                        actual_clear_mask = 0x00;
                        actual_data_extract_mask = 0xFF;
                    } else if active_lsb_bits > 0 && active_lsb_bits < 8 { // Handles 1-7
                        actual_clear_mask = 0xFF << active_lsb_bits;
                        actual_data_extract_mask = (1 << active_lsb_bits) - 1;
                    } else {
                        // Should not happen given current logic (lsb_for_header=1, lsb_bits_per_channel=1-4 or 8)
                        return Err(CryptoImageError::InvalidParameter(format!("Invalid active_lsb_bits: {}", active_lsb_bits)));
                    }


                    let mut bits_for_channel: u8 = 0;
                    for bit_k in 0..active_lsb_bits {
                        if bit_idx_overall < active_total_bits {
                            let data_byte = active_data_source[current_data_source_byte_idx];
                            let current_data_bit = (data_byte >> current_data_source_bit_idx) & 1;
                            bits_for_channel |= current_data_bit << bit_k;
                            
                            bit_idx_overall += 1;
                            current_data_source_bit_idx += 1;
                            if current_data_source_bit_idx == 8 {
                                current_data_source_bit_idx = 0;
                                current_data_source_byte_idx += 1;
                            }
                        } else {
                            break; 
                        }
                    }
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & actual_clear_mask) | (bits_for_channel & actual_data_extract_mask);
                }
            }
        }
        
        if embedding_header || bit_idx_overall < total_payload_bits {
             return Err(CryptoImageError::Steganography(
                    format!("Carrier image too small. Header embedded: {}, Payload bits embedded: {}/{}.", !embedding_header, bit_idx_overall, total_payload_bits)
            ));
        }

        let final_output_path = output_path_base.with_extension("png");
        carrier_image.save(&final_output_path)?;
        println!("Image encrypted successfully to (Steganography PNG): {:?}", final_output_path);
    } else {
        return Err(CryptoImageError::InvalidParameter(format!("Unsupported output format: {}", config.output_format_preference)));
    }

    Ok(original_extension_str) // Return the original extension (as string)
}

/// Encrypts an image file using AES-256-GCM. Derives key and salt internally.
/// This is the standard entry point for single-file encryption.
pub fn encrypt_file<P1: AsRef<Path> + std::fmt::Debug, P2: AsRef<Path> + std::fmt::Debug, P3: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P1,
    output_encrypted_path_param: P2,
    secret: &Zeroizing<String>, // Takes the raw secret
    output_format_preference: &str,
    base_image_path_opt: Option<P3>,
    lsb_bits_per_channel: u8, 
    app_version: (u8, u8, u8),
) -> Result<String, CryptoImageError> {
    // Generate a new random salt for Argon2.
    let new_salt = SaltString::generate(&mut OsRng);
    // Derive the encryption key from the secret and salt using Argon2.
    let derived_key = derive_encryption_key_with_salt(secret, &new_salt)?;

    let core_config = EncryptionCoreConfig {
        output_format_preference,
        base_image_path_opt,
        lsb_bits_per_channel,
        app_version,
    };

    // Call the core encryption logic with the derived key and new salt.
    encrypt_file_core(
        input_image_path,
        output_encrypted_path_param,
        &derived_key,
        &new_salt,
        &core_config,
    )
}

/// Processes all supported files in an input directory for encryption.
/// Uses a single derived key and salt for all files in the folder.
/// Can operate recursively if `is_recursive` is true.
fn process_folder_encryption_recursive_helper(
    current_input_dir: &Path,
    current_output_dir: &Path,
    derived_key: &[u8; 32],
    salt_for_folder: &SaltString,
    output_format_preference: &str,
    base_image_path_opt: Option<&Path>,
    lsb_bits: u8,
    app_version: (u8, u8, u8),
    is_recursive: bool,
    files_processed_successfully: &mut u32,
    files_failed_to_process: &mut u32,
    files_skipped_extension: &mut u32,
) {
    match fs::read_dir(current_input_dir) {
        Ok(entries) => {
            for entry_result in entries {
                match entry_result {
                    Ok(entry) => {
                        let current_input_file_path = entry.path();
                        let file_name_os_str = current_input_file_path.file_name().unwrap_or_default();
                        let input_filename_complete_str = file_name_os_str.to_string_lossy();

                        if current_input_file_path.is_dir() {
                            if is_recursive {
                                // Skip hidden directories like .git, .vscode etc.
                                if input_filename_complete_str.starts_with('.') {
                                    println!("Skipping hidden directory: {:?}", current_input_file_path);
                                    continue;
                                }
                                println!("Entering directory: {:?}", current_input_file_path);
                                let next_output_dir = current_output_dir.join(file_name_os_str);
                                if !next_output_dir.exists() {
                                    if let Err(e) = fs::create_dir_all(&next_output_dir) {
                                        eprintln!("Error: Could not create output subdirectory '{:?}': {}", next_output_dir, e);
                                        *files_failed_to_process += 1; // Count this as a failure for the parent dir processing
                                        continue;
                                    }
                                }
                                // Recursive call
                                process_folder_encryption_recursive_helper(
                                    &current_input_file_path,
                                    &next_output_dir,
                                    derived_key,
                                    salt_for_folder,
                                    output_format_preference,
                                    base_image_path_opt,
                                    lsb_bits,
                                    app_version,
                                    is_recursive,
                                    files_processed_successfully,
                                    files_failed_to_process,
                                    files_skipped_extension,
                                );
                            } else {
                                // Skip directory if not in recursive mode
                                println!("Skipping directory (non-recursive mode): {:?}", current_input_file_path);
                            }
                        } else if current_input_file_path.is_file() {
                            // Skip hidden files (e.g., .DS_Store) robustly
                            if input_filename_complete_str.starts_with('.') {
                                *files_skipped_extension +=1;
                                continue; // Silently skip hidden files
                            }

                            let new_base_name = format!("{}.encrypted", input_filename_complete_str);
                            let current_output_file_path_base = current_output_dir.join(new_base_name);

                            print!("Encrypting {:?} -> {:?} (final extension .{}) ... ",
                                   current_input_file_path,
                                   current_output_file_path_base,
                                   output_format_preference);
                            
                            let core_config = EncryptionCoreConfig {
                                output_format_preference,
                                base_image_path_opt,
                                lsb_bits_per_channel: lsb_bits,
                                app_version,
                            };

                            match encrypt_file_core(
                                &current_input_file_path,
                                &current_output_file_path_base,
                                derived_key,
                                salt_for_folder,
                                &core_config,
                            ) {
                                Ok(_) => {
                                    println!("Done.");
                                    *files_processed_successfully += 1;
                                }
                                Err(e) => {
                                    eprintln!("\nError encrypting file {:?}: {}", current_input_file_path, e);
                                    *files_failed_to_process += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading a directory entry in {:?}: {}", current_input_dir, e);
                        *files_failed_to_process += 1;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error: Could not read input directory '{:?}': {}", current_input_dir, e);
            *files_failed_to_process +=1;
        }
    }
}

pub fn process_folder_encryption(
    input_dir_str: &str,
    output_dir_str: &str,
    encryption_secret: &Zeroizing<String>,
    output_format_preference: &str,
    base_image_path_str_opt: Option<&String>,
    lsb_bits: u8,
    app_version: (u8, u8, u8),
    is_recursive: bool,
) {
    let input_dir = Path::new(input_dir_str);
    let output_dir = Path::new(output_dir_str);

    // Generate salt and derive key ONCE for the entire folder operation
    let salt_for_folder = SaltString::generate(&mut OsRng);
    let derived_key = match derive_encryption_key_with_salt(encryption_secret, &salt_for_folder) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error deriving key for folder encryption: {}", e);
            std::process::exit(1); 
        }
    };

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

    let mut files_processed_successfully = 0;
    let mut files_failed_to_process = 0;
    let mut files_skipped_extension = 0;
    println!("\nStarting folder encryption (Recursive: {})...", is_recursive);

    // Map Option<&String> to Option<PathBuf> for the helper
    let base_path_for_core_opt_owned: Option<PathBuf> = base_image_path_str_opt.map(|s| PathBuf::from(s.as_str()));
    // Then convert Option<PathBuf> to Option<&Path> for the helper function
    let base_path_for_helper: Option<&Path> = base_path_for_core_opt_owned.as_deref();

    process_folder_encryption_recursive_helper(
        input_dir,
        output_dir,
        &derived_key,
        &salt_for_folder,
        output_format_preference,
        base_path_for_helper,
        lsb_bits,
        app_version,
        is_recursive,
        &mut files_processed_successfully,
        &mut files_failed_to_process,
        &mut files_skipped_extension,
    );
    
    println!("\nFolder encryption summary:");
    println!("  Files successfully encrypted: {}", files_processed_successfully);
    println!("  Files failed to encrypt: {}", files_failed_to_process);
    if files_skipped_extension > 0 {
        println!("  Files skipped (e.g. hidden or previously filtered): {}", files_skipped_extension);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;
    use crate::decrypt::decrypt_file; 
    use crate::error_types::CryptoImageError;
    use image::{RgbImage, ImageFormat, GenericImageView};

    // Helper function to create a dummy PNG file for testing base image functionality.
    fn create_dummy_png(path: &Path, width: u32, height: u32) -> Result<(), CryptoImageError> {
        let mut img = RgbImage::new(width, height);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
        }
        img.save_with_format(path, ImageFormat::Png)?;
        Ok(())
    }

    #[test]
    fn test_prepare_carrier_image_no_base() -> Result<(), CryptoImageError> {
        let pixels_needed = 100;
        let carrier = prepare_carrier_image::<PathBuf>(None, pixels_needed)?;
        assert_eq!((carrier.width() as usize) * (carrier.height() as usize), pixels_needed, "Generated image should have area equal to pixels_needed");
        // For a square-ish image for 100 pixels, it would be 10x10.
        // prepare_carrier_image aims for width = ceil(sqrt(pixels_needed)), height = ceil(pixels_needed / width)
        // sqrt(100) = 10. width = 10. height = 100/10 = 10.
        assert_eq!(carrier.width(), 10);
        assert_eq!(carrier.height(), 10);
        Ok(())
    }

    #[test]
    fn test_prepare_carrier_image_base_larger() -> Result<(), CryptoImageError> {
        let temp_dir = tempdir()?;
        let base_path = temp_dir.path().join("base_larger.png");
        create_dummy_png(&base_path, 20, 20)?; // 400 pixels

        let pixels_needed = 100;
        let carrier = prepare_carrier_image(Some(&base_path), pixels_needed)?;
        assert_eq!(carrier.width(), 20);
        assert_eq!(carrier.height(), 20); // Should use the original base image as is
        
        // Verify content is from base_path (simple check, e.g. first pixel)
        let original_base_img = image::open(&base_path)?.to_rgb8();
        assert_eq!(carrier.get_pixel(0,0), original_base_img.get_pixel(0,0));

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_prepare_carrier_image_base_smaller_needs_tiling() -> Result<(), CryptoImageError> {
        let temp_dir = tempdir()?;
        let base_path = temp_dir.path().join("base_smaller.png");
        create_dummy_png(&base_path, 5, 5)?; // 25 pixels

        let pixels_needed = 100; // Needs 4x tiling (5x5 -> 10x10)
        let carrier = prepare_carrier_image(Some(&base_path), pixels_needed)?;
        
        // Expected dimensions after tiling to fit 100 pixels from a 5x5 base:
        // 5*num_tiles_x * 5*num_tiles_y >= 100
        // If num_tiles_x = 2, num_tiles_y = 2 => 10 * 10 = 100 pixels.
        assert_eq!(carrier.width(), 10, "Carrier width should be tiled correctly");
        assert_eq!(carrier.height(), 10, "Carrier height should be tiled correctly");
        assert_eq!((carrier.width() * carrier.height()) as usize, pixels_needed);

        // Check if tiling pattern is correct (e.g. pixel (5,0) should be same as (0,0) from original)
        let original_base_img = image::open(&base_path)?.to_rgb8();
        assert_eq!(carrier.get_pixel(0,0), original_base_img.get_pixel(0,0));
        assert_eq!(carrier.get_pixel(5,0), original_base_img.get_pixel(0,0)); // Tiled horizontally
        assert_eq!(carrier.get_pixel(0,5), original_base_img.get_pixel(0,0)); // Tiled vertically
        assert_eq!(carrier.get_pixel(5,5), original_base_img.get_pixel(0,0)); // Tiled diagonally

        temp_dir.close()?;
        Ok(())
    }
    
    #[test]
    fn test_prepare_carrier_image_base_not_found() {
        let base_path = PathBuf::from("non_existent_base.png");
        let pixels_needed = 100;
        let result = prepare_carrier_image(Some(&base_path), pixels_needed);
        assert!(matches!(result, Err(CryptoImageError::Io(_))));
    }

    #[test]
    fn test_prepare_carrier_image_base_not_png() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let base_path = temp_dir.path().join("base_not_png.jpg");
        // Create a dummy file that is not a PNG
        fs::write(&base_path, b"this is not a png")?;

        let pixels_needed = 100;
        let result = prepare_carrier_image(Some(&base_path), pixels_needed);
        assert!(matches!(result, Err(CryptoImageError::InvalidParameter(_))));
        
        temp_dir.close()?;
        Ok(())
    }


    #[test]
    fn test_encrypt_decrypt_round_trip_txt() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input.dat"); // Changed to .dat to test generic extension
        let encrypted_path = temp_dir.path().join("test_encrypted");
        let decrypted_path_base = temp_dir.path().join("test_decrypted"); // Base for decrypted output

        let original_data = b"This is some test image data for TXT format with a .dat extension.";
        fs::write(&input_image_path, original_data)?;

        let secret = Zeroizing::new("supersecretpassword123!@#".to_string());
        let output_format_preference = "txt";
        let lsb_bits: u8 = 1;
        let app_version_for_test = (1,0,0); // Example app_version for tests

        encrypt_file(
            &input_image_path,
            &encrypted_path,
            &secret,
            output_format_preference,
            None::<PathBuf>,
            lsb_bits,
            app_version_for_test, 
        )?;

        let encrypted_file_with_ext = encrypted_path.with_extension("txt");
        assert!(encrypted_file_with_ext.exists(), "Encrypted TXT file should exist.");

        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Pass base path
            &secret,
            app_version_for_test,
        )?;
        
        // Decrypted file should now be test_decrypted.dat
        let decrypted_file_with_original_ext = decrypted_path_base.with_extension("dat");
        assert!(decrypted_file_with_original_ext.exists(), "Decrypted file with original extension .dat should exist.");
        let decrypted_data_content = fs::read(&decrypted_file_with_original_ext)?;
        assert_eq!(original_data.to_vec(), decrypted_data_content, "Decrypted data should match original for TXT format.");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_png_no_base() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input_for_png.png");
        let encrypted_path_base = temp_dir.path().join("test_encrypted_steg");
        let decrypted_path_base = temp_dir.path().join("test_decrypted_steg");

        let original_png_width = 20;
        let original_png_height = 10;
        create_dummy_png(&input_image_path, original_png_width, original_png_height)?;
        let original_data = fs::read(&input_image_path)?;

        let secret = Zeroizing::new("anotherStrongPassword!$5^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 2;
        let app_version_for_test = (1,0,0); // Example app_version for tests

        let original_input_format = encrypt_file(
            &input_image_path,
            &encrypted_path_base,
            &secret,
            output_format_preference,
            None::<PathBuf>,
            lsb_bits,
            app_version_for_test, 
        )?;
        assert_eq!(original_input_format, "png");

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file should exist.");

        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base,
            &secret,
            app_version_for_test,
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
        let input_image_path = temp_dir.path().join("test_input_for_steg_base.any"); // Test with a generic extension
        let base_image_path = temp_dir.path().join("base_carrier.png");
        let encrypted_path_base = temp_dir.path().join("test_encrypted_steg_w_base");
        let decrypted_path_base = temp_dir.path().join("test_decrypted_steg_w_base");

        let data_to_encrypt = b"A bit longer payload for steganography with base image to ensure multiple pixels are used with multi-LSB.";
        fs::write(&input_image_path, data_to_encrypt)?;
        
        create_dummy_png(&base_image_path, 30, 30)?;

        let secret = Zeroizing::new("passwordForStegWithBase123$%^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 3;
        let app_version_for_test = (1,0,0); // Example app_version for tests

        encrypt_file(
            &input_image_path,
            &encrypted_path_base,
            &secret,
            output_format_preference,
            Some(&base_image_path),
            lsb_bits,
            app_version_for_test, 
        )?;

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file (with base) should exist.");

        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Pass base path
            &secret,
            app_version_for_test,
        )?;
        
        // Decrypted file should now be test_decrypted_steg_w_base.any
        let decrypted_file_with_original_ext = decrypted_path_base.with_extension("any");
        assert!(decrypted_file_with_original_ext.exists(), "Decrypted file with original extension .any should exist.");
        let decrypted_data_content = fs::read(&decrypted_file_with_original_ext)?;
        assert_eq!(data_to_encrypt.to_vec(), decrypted_data_content, "Decrypted data should match original for steganographic PNG (with base).");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_empty_file_txt() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_file_path = temp_dir.path().join("empty_input.nodata"); // Test with a generic extension
        let encrypted_path_base = temp_dir.path().join("empty_encrypted_txt");
        let decrypted_path_base = temp_dir.path().join("empty_decrypted_txt");

        fs::write(&input_file_path, b"")?; // Empty file

        let secret = Zeroizing::new("TestSecretForEmptyFile1!".to_string());
        let output_format = "txt";
        let lsb_bits = 1; // Not used for txt
        let app_version_for_test = (1,0,0); // Example app_version for tests

        encrypt_file(
            &input_file_path,
            &encrypted_path_base,
            &secret,
            output_format,
            None::<PathBuf>, // No base image
            lsb_bits,
            app_version_for_test, 
        )?;

        let encrypted_file_with_ext = encrypted_path_base.with_extension("txt");
        assert!(encrypted_file_with_ext.exists());

        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Pass base path
            &secret,
            app_version_for_test,
        )?;
        
        // Decrypted file should be empty_decrypted_txt.nodata
        let decrypted_file_with_original_ext = decrypted_path_base.with_extension("nodata");
        assert!(decrypted_file_with_original_ext.exists(), "Decrypted file with original extension .nodata should exist.");
        let decrypted_data = fs::read(&decrypted_file_with_original_ext)?;
        assert_eq!(decrypted_data, b"", "Decrypted data for empty file should be empty.");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_empty_file_png_no_base() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_file_path = temp_dir.path().join("empty_input_for_png.bin"); // Test with a generic extension
        let encrypted_path_base = temp_dir.path().join("empty_encrypted_png");
        let decrypted_path_base = temp_dir.path().join("empty_decrypted_png");

        fs::write(&input_file_path, b"")?; // Empty file

        let secret = Zeroizing::new("TestSecretForEmptyPng1!".to_string());
        let output_format = "png";
        // When no base image, lsb_bits is effectively 8, but the param is passed.
        // The actual lsb_bits_per_channel used for embedding is 8.
        let lsb_bits_param = 8; 
        let app_version_for_test = (1,0,0); // Example app_version for tests

        encrypt_file(
            &input_file_path,
            &encrypted_path_base,
            &secret,
            output_format,
            None::<PathBuf>, // No base image
            lsb_bits_param,
            app_version_for_test, 
        )?;

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted PNG file should exist.");

        // Check carrier image size for empty payload (salt + nonce + 0 bytes data)
        // Header (5 bytes) + Salt (22 bytes) + ExtLen (1 byte) + Ext ("bin" -> 3 bytes) + Nonce (12 bytes) = 43 bytes.
        // Header bits = 5 * 8 = 40 bits. Pixels for header (1 LSB/channel) = ceil(40 / (3*1)) = 14 pixels
        // Payload bits = (22+1+3+12) * 8 = 38 * 8 = 304 bits. Pixels for payload (8 LSB/channel) = ceil(304 / (3*8)) = ceil(304/24) = 13 pixels
        // Total pixels needed = 14 + 13 = 27 pixels.
        // prepare_carrier_image will create sqrt(27) ~ 5.19 -> 6x5 or 6x6 image (e.g. 6x5=30 pixels)
        let carrier_img = image::open(&encrypted_file_with_ext)?;
        assert!((carrier_img.width() * carrier_img.height()) >= 27, "Carrier image for empty payload is too small.");


        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Pass base path
            &secret,
            app_version_for_test,
        )?;
        
        // Decrypted file should be empty_decrypted_png.bin
        let decrypted_file_with_original_ext = decrypted_path_base.with_extension("bin");
        assert!(decrypted_file_with_original_ext.exists(), "Decrypted file with original extension .bin should exist.");
        let decrypted_data = fs::read(&decrypted_file_with_original_ext)?;
        assert_eq!(decrypted_data, b"", "Decrypted data for empty file (PNG) should be empty.");

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_steganography_carrier_too_small_for_payload() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_file_path = temp_dir.path().join("large_payload.dat"); // .dat extension
        let base_image_path = temp_dir.path().join("tiny_carrier.png");
        let encrypted_path_base = temp_dir.path().join("encrypted_output");
        let decrypted_path_base = temp_dir.path().join("decrypted_output_for_tiled");

        // Create a large payload
        let large_data = vec![0u8; 1000]; // 1000 bytes
        fs::write(&input_file_path, &large_data)?;
        
        // Create a very small base image (e.g., 1x1 pixel)
        create_dummy_png(&base_image_path, 1, 1)?;

        let secret = Zeroizing::new("TinyCarrierTestSecret1!".to_string());
        let output_format = "png";
        let lsb_bits = 1; // 1 LSB per channel
        let app_version_for_test = (1,0,0); // Example app_version for tests

        // Encrypt_image should succeed by tiling the small base image.
        let result = encrypt_file(
            &input_file_path,
            &encrypted_path_base,
            &secret,
            output_format,
            Some(&base_image_path),
            lsb_bits,
            app_version_for_test, 
        );
        assert!(result.is_ok(), "Encryption should succeed by tiling the small base image. Error: {:?}", result.err());

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted PNG file should exist.");

        // Verify that the output image was tiled (i.e., is larger than 1x1)
        let output_image = image::open(&encrypted_file_with_ext)?;
        let (output_width, output_height) = output_image.dimensions(); // Now GenericImageView is in scope
        assert!(output_width > 1 || output_height > 1, "Output image should be larger than the 1x1 base image due to tiling.");

        // Calculate expected pixels needed to confirm sufficient tiling
        // Payload: 1000 bytes. AES-GCM tag: 16 bytes. Total encrypted: 1016 bytes.
        // Raw output payload: salt (22) + ext_len (1) + ext ("dat" -> 3) + nonce (12) + encrypted_data (1016) = 1054 bytes.
        // Header: lsb_config (1) + payload_len (4) = 5 bytes.
        // Total header bits: 5 * 8 = 40 bits. Bits per pixel for header (1 LSB/channel): 3.
        // Pixels for header: ceil(40/3) = 14.
        // Total payload bits: 1054 * 8 = 8432 bits. Bits per pixel for payload (1 LSB/channel): 3.
        // Pixels for payload: ceil(8432/3) = 2811.
        // Total pixels needed: 14 + 2811 = 2825.
        let expected_pixels_needed = 2825;
        assert!((output_width as usize * output_height as usize) >= expected_pixels_needed, 
                "Output image capacity ({}) should be >= expected_pixels_needed ({})", 
                output_width as usize * output_height as usize, expected_pixels_needed);


        // Decrypt and verify data
        decrypt_file(
            &encrypted_file_with_ext,
            &decrypted_path_base, // Pass base path
            &secret,
            app_version_for_test,
        )?;

        // Decrypted file should be decrypted_output_for_tiled.dat
        let decrypted_file_with_original_ext = decrypted_path_base.with_extension("dat");
        assert!(decrypted_file_with_original_ext.exists(), "Decrypted file with original extension .dat should exist.");
        let decrypted_data_content = fs::read(&decrypted_file_with_original_ext)?;
        assert_eq!(large_data, decrypted_data_content, "Decrypted data should match original after tiling.");

        temp_dir.close()?;
        Ok(())
    }
}
