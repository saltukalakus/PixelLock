use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use image::{RgbImage};
use rand::{rngs::OsRng, Rng, random};
use std::{fs, path::{Path, PathBuf}};
use argon2::password_hash::SaltString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};

use crate::error_types::CryptoImageError;
use crate::utils::{SALT_STRING_LEN, NONCE_STRING_LEN, derive_encryption_key_with_salt};

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
        if (!base_path.exists()) {
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
/// * `Err(CryptoImageError)` on failure.
pub fn encrypt_image<P1: AsRef<Path> + std::fmt::Debug, P2: AsRef<Path> + std::fmt::Debug, P3: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P1,
    output_encrypted_path_param: P2,
    secret: &Zeroizing<String>,
    output_format_preference: &str,
    base_image_path_opt: Option<P3>,
    lsb_bits_per_channel: u8, 
) -> Result<String, CryptoImageError> {
    let original_format_str = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("png")
        .to_lowercase();

    // Read the entire input image file into bytes.
    let img_bytes = fs::read(&input_image_path)?;

    // Generate a new random salt for Argon2.
    let salt: SaltString = SaltString::generate(&mut OsRng);
    // Derive the encryption key from the secret and salt using Argon2.
    let derived_key = derive_encryption_key_with_salt(secret, &salt)?;

    // Initialize AES-256-GCM cipher with the derived key.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    // Generate a random nonce for AES-GCM.
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the image data.
    let encrypted_data_core = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| CryptoImageError::Encryption("AEAD encryption failed".to_string()))?;

    let salt_bytes_to_store = salt.as_str().as_bytes();
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
        let lsb_config_byte = lsb_bits_per_channel; 
        let payload_len_bytes = (raw_output_payload.len() as u32).to_be_bytes();

        let mut header_to_embed = vec![lsb_config_byte];
        header_to_embed.extend_from_slice(&payload_len_bytes);

        let total_header_bits = header_to_embed.len() * 8;
        let total_payload_bits = raw_output_payload.len() * 8;

        let lsb_for_header: u8 = 1;
        let bits_per_pixel_header = 3 * lsb_for_header as usize;
        let bits_per_pixel_payload = 3 * lsb_bits_per_channel as usize;

        if bits_per_pixel_payload == 0 {
            return Err(CryptoImageError::InvalidParameter("LSB bits per channel for payload cannot be zero.".to_string()));
        }

        let pixels_needed_for_header = total_header_bits.div_ceil(bits_per_pixel_header);
        let pixels_needed_for_payload = total_payload_bits.div_ceil(bits_per_pixel_payload);
        let pixels_needed = pixels_needed_for_header + pixels_needed_for_payload;

        // Prepare or create the carrier image using the helper function.
        let mut carrier_image = prepare_carrier_image(base_image_path_opt, pixels_needed)?;
        
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
                        (&raw_output_payload, lsb_bits_per_channel, total_payload_bits)
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
                        // but as a fallback, treat as no-op or error.
                        // For safety, let's assume it means 0 bits, effectively a no-op on this channel.
                        actual_clear_mask = 0xFF; 
                        actual_data_extract_mask = 0x00;
                        // Or, return an error:
                        // return Err(CryptoImageError::InvalidParameter(format!("Invalid active_lsb_bits: {}", active_lsb_bits)));
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
        return Err(CryptoImageError::InvalidParameter(format!("Unsupported output format: {}", output_format_preference)));
    }

    Ok(original_format_str)
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;
    use crate::decrypt::decrypt_image; // Corrected: For round-trip testing
    use crate::error_types::CryptoImageError;
    use image::{RgbImage, ImageFormat}; // Corrected: Removed 'random' from here
    // Note: 'random' function is brought into scope by `use super::*;` 
    // from the top-level `use rand::{..., random};`


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
    fn test_encrypt_decrypt_round_trip_txt() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let input_image_path = temp_dir.path().join("test_input.dat");
        let encrypted_path = temp_dir.path().join("test_encrypted");
        let decrypted_path = temp_dir.path().join("test_decrypted");

        let original_data = b"This is some test image data for TXT format.";
        fs::write(&input_image_path, original_data)?;

        let secret = Zeroizing::new("supersecretpassword123!@#".to_string());
        let output_format_preference = "txt";
        let lsb_bits: u8 = 1;

        encrypt_image(
            &input_image_path,
            &encrypted_path,
            &secret,
            output_format_preference,
            None::<PathBuf>,
            lsb_bits,
        )?;

        let encrypted_file_with_ext = encrypted_path.with_extension("txt");
        assert!(encrypted_file_with_ext.exists(), "Encrypted TXT file should exist.");

        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path,
            &secret,
        )?;
        
        let decrypted_data_content = fs::read(&decrypted_path)?;
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

        let original_input_format = encrypt_image(
            &input_image_path,
            &encrypted_path_base,
            &secret,
            output_format_preference,
            None::<PathBuf>,
            lsb_bits,
        )?;
        assert_eq!(original_input_format, "png");

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file should exist.");

        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path_base,
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

        let data_to_encrypt = b"A bit longer payload for steganography with base image to ensure multiple pixels are used with multi-LSB.";
        fs::write(&input_image_path, data_to_encrypt)?;
        
        create_dummy_png(&base_image_path, 30, 30)?;

        let secret = Zeroizing::new("passwordForStegWithBase123$%^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 3;

        encrypt_image(
            &input_image_path,
            &encrypted_path_base,
            &secret,
            output_format_preference,
            Some(&base_image_path),
            lsb_bits,
        )?;

        let encrypted_file_with_ext = encrypted_path_base.with_extension("png");
        assert!(encrypted_file_with_ext.exists(), "Encrypted steganographic PNG file (with base) should exist.");

        decrypt_image(
            &encrypted_file_with_ext,
            &decrypted_path_base,
            &secret,
        )?;
        
        assert!(decrypted_path_base.exists(), "Decrypted file (with base) should exist.");
        let decrypted_data_content = fs::read(&decrypted_path_base)?;
        assert_eq!(data_to_encrypt.to_vec(), decrypted_data_content, "Decrypted data should match original for steganographic PNG (with base).");

        temp_dir.close()?;
        Ok(())
    }
}
