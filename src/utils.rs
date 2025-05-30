use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Error as AeadError};
use image::{ImageError as ImgError, RgbImage, GenericImageView}; // Removed ImageFormat
use rand::{rngs::OsRng, Rng, random};
use std::{array::TryFromSliceError, fmt, fs, path::{Path, PathBuf}}; // Added TryFromSliceError
use argon2::{Argon2, PasswordHasher, Error as Argon2Error};
use argon2::password_hash::{SaltString, Error as PasswordHashError};
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose, DecodeError as Base64DecodeError};

// Custom Error Type
#[derive(Debug)]
pub enum CryptoImageError {
    Io(std::io::Error),
    Image(ImgError),
    Encryption(String),
    Decryption(String),
    Aead(AeadError),
    Argon2(Argon2Error),
    PasswordHash(PasswordHashError),
    Base64(Base64DecodeError),
    Steganography(String),
    PasswordComplexity(String),
    InvalidParameter(String),
    Utf8Error(std::str::Utf8Error),
    TryFromSlice(TryFromSliceError), // Added variant
}

impl fmt::Display for CryptoImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoImageError::Io(e) => write!(f, "IO error: {}", e),
            CryptoImageError::Image(e) => write!(f, "Image processing error: {}", e),
            CryptoImageError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            CryptoImageError::Decryption(msg) => write!(f, "Decryption error: {}", msg),
            CryptoImageError::Aead(_) => write!(f, "AEAD operation error"),
            CryptoImageError::Argon2(e) => write!(f, "Argon2 error: {}", e),
            CryptoImageError::PasswordHash(e) => write!(f, "Password hashing error: {}", e),
            CryptoImageError::Base64(e) => write!(f, "Base64 decoding error: {}", e),
            CryptoImageError::Steganography(msg) => write!(f, "Steganography error: {}", msg),
            CryptoImageError::PasswordComplexity(msg) => write!(f, "Password complexity error: {}", msg),
            CryptoImageError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            CryptoImageError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            CryptoImageError::TryFromSlice(e) => write!(f, "Slice to array conversion error: {}", e), // Added display
        }
    }
}

impl std::error::Error for CryptoImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoImageError::Io(e) => Some(e),
            CryptoImageError::Image(e) => Some(e),
            CryptoImageError::Aead(_) => None, // aead::Error is (), does not implement Error
            CryptoImageError::Argon2(_) => None, // argon2::Error source() returns None
            CryptoImageError::PasswordHash(_) => None, // password_hash::Error source() returns None
            CryptoImageError::Base64(e) => Some(e),
            CryptoImageError::Utf8Error(e) => Some(e),
            CryptoImageError::TryFromSlice(e) => Some(e), 
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoImageError {
    fn from(err: std::io::Error) -> Self {
        CryptoImageError::Io(err)
    }
}

impl From<ImgError> for CryptoImageError {
    fn from(err: ImgError) -> Self {
        CryptoImageError::Image(err)
    }
}

impl From<AeadError> for CryptoImageError { // aes_gcm::Error is an alias for aead::Error which is ()
    fn from(err: AeadError) -> Self {
        CryptoImageError::Aead(err)
    }
}

impl From<Argon2Error> for CryptoImageError {
    fn from(err: Argon2Error) -> Self {
        CryptoImageError::Argon2(err)
    }
}

impl From<PasswordHashError> for CryptoImageError {
    fn from(err: PasswordHashError) -> Self {
        CryptoImageError::PasswordHash(err)
    }
}

impl From<Base64DecodeError> for CryptoImageError {
    fn from(err: Base64DecodeError) -> Self {
        CryptoImageError::Base64(err)
    }
}

impl From<std::str::Utf8Error> for CryptoImageError {
    fn from(err: std::str::Utf8Error) -> Self {
        CryptoImageError::Utf8Error(err)
    }
}

impl From<TryFromSliceError> for CryptoImageError { // Added From impl
    fn from(err: TryFromSliceError) -> Self {
        CryptoImageError::TryFromSlice(err)
    }
}

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
/// * `Err(CryptoImageError)` on failure.
pub fn encrypt_image<P1: AsRef<Path> + std::fmt::Debug, P2: AsRef<Path> + std::fmt::Debug, P3: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P1,
    output_encrypted_path_param: P2,
    secret: &Zeroizing<String>,
    output_format_preference: &str,
    base_image_path_opt: Option<P3>,
    lsb_bits_per_channel: u8, 
) -> Result<String, CryptoImageError> { // Changed return type
    let original_format_str = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("png")
        .to_lowercase();

    // Read the entire input image file into bytes.
    let img_bytes = fs::read(&input_image_path)?; // Uses From<std::io::Error>

    // Generate a new random salt for Argon2.
    let salt: SaltString = SaltString::generate(&mut OsRng);
    // Derive the encryption key from the secret and salt using Argon2.
    let derived_key = derive_encryption_key_with_salt(secret, &salt)?; // Changed

    // Initialize AES-256-GCM cipher with the derived key.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    // Generate a random nonce for AES-GCM.
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the image data.
    let encrypted_data_core = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| CryptoImageError::Encryption("AEAD encryption failed".to_string()))?; // Changed

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
        // Steganography for PNG
        // Header: [1 byte for lsb_bits_per_channel used for payload] + [4 bytes for raw_output_payload length]
        // Payload: raw_output_payload
        
        let lsb_config_byte = lsb_bits_per_channel; // u8, values 1-4
        let payload_len_bytes = (raw_output_payload.len() as u32).to_be_bytes();

        let mut header_to_embed = vec![lsb_config_byte];
        header_to_embed.extend_from_slice(&payload_len_bytes); // 5 bytes total for header

        let total_header_bits = header_to_embed.len() * 8;
        let total_payload_bits = raw_output_payload.len() * 8;

        let lsb_for_header: u8 = 1; // Header is always embedded with 1 LSB per channel
        let bits_per_pixel_header = 3 * lsb_for_header as usize;
        let bits_per_pixel_payload = 3 * lsb_bits_per_channel as usize;

        if bits_per_pixel_payload == 0 {
            return Err(CryptoImageError::InvalidParameter("LSB bits per channel for payload cannot be zero.".to_string())); // Changed
        }

        let pixels_needed_for_header = total_header_bits.div_ceil(bits_per_pixel_header);
        let pixels_needed_for_payload = total_payload_bits.div_ceil(bits_per_pixel_payload);
        let pixels_needed = pixels_needed_for_header + pixels_needed_for_payload;

        let mut carrier_image: RgbImage;

        // Determine the carrier image: use provided base image or generate a new one.
        if let Some(base_path_ref) = base_image_path_opt {
            // Load and prepare the user-provided base image.
            let base_path = base_path_ref.as_ref();
            if !base_path.exists() {
                return Err(CryptoImageError::Io(std::io::Error::new( // Changed
                    std::io::ErrorKind::NotFound,
                    format!("Base image not found: {:?}", base_path),
                )));
            }
            if base_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() != "png" {
                return Err(CryptoImageError::InvalidParameter("Base image must be a PNG file.".to_string())); // Changed
            }

            let base_dyn_image = image::open(base_path)?; // Uses From<ImgError>
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
            if width == 0 { return Err(CryptoImageError::InvalidParameter("Calculated width is zero for new image".into()));} // Changed
            if height == 0 { height = 1; }

            carrier_image = RgbImage::new(width, height);
            // Fill the new image with random pixels.
            for pixel_val in carrier_image.pixels_mut() {
                *pixel_val = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
            }
        }
        
        // Embed data into the carrier image using LSB steganography.
        let (img_width, img_height) = carrier_image.dimensions();
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
                            embedding_header = false; // Switch to payload
                            bit_idx_overall = 0; // Reset bit index for payload
                            current_data_source_byte_idx = 0;
                            current_data_source_bit_idx = 0;
                            if total_payload_bits == 0 { break 'embedding_loop; } // No payload to embed
                        } else {
                            break 'embedding_loop; // All data (header and payload) embedded.
                        }
                    }
                    
                    // Re-evaluate masks and LSBs for the current stage (header or payload)
                    let (active_data_source, active_lsb_bits, active_total_bits) = if embedding_header {
                        (&header_to_embed, lsb_for_header, total_header_bits)
                    } else {
                        (&raw_output_payload, lsb_bits_per_channel, total_payload_bits)
                    };

                    if bit_idx_overall >= active_total_bits { // Check again after potential stage switch
                         if embedding_header { // Should not happen if logic above is correct
                             embedding_header = false; 
                             bit_idx_overall = 0; 
                             current_data_source_byte_idx = 0;
                             current_data_source_bit_idx = 0;
                             if total_payload_bits == 0 { break 'embedding_loop; }
                             continue; // restart channel loop with new settings
                         } else {
                             break 'embedding_loop;
                         }
                    }

                    let current_clear_mask: u8 = 0xFF << active_lsb_bits;
                    let current_data_extract_mask: u8 = (1 << active_lsb_bits) - 1;

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
                    pixel.0[channel_idx] = (pixel.0[channel_idx] & current_clear_mask) | (bits_for_channel & current_data_extract_mask);
                }
            }
        }
        
        // Ensure all data was embedded.
        if embedding_header || bit_idx_overall < total_payload_bits {
             return Err(CryptoImageError::Steganography( // Changed
                    format!("Carrier image too small. Header embedded: {}, Payload bits embedded: {}/{}.", !embedding_header, bit_idx_overall, total_payload_bits)
            ));
        }

        // Save the steganographic image.
        let final_output_path = output_path_base.with_extension("png");
        carrier_image.save(&final_output_path)?; // Uses From<ImgError>
        println!("Image encrypted successfully to (Steganography PNG): {:?}", final_output_path);
    } else {
        return Err(CryptoImageError::InvalidParameter(format!("Unsupported output format: {}", output_format_preference))); // Changed
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
/// * `Err(CryptoImageError)` on failure.
pub fn decrypt_image<PIn: AsRef<Path> + std::fmt::Debug, POut: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path_ref: PIn,
    output_decrypted_path_base: POut,
    secret: &Zeroizing<String>,
) -> Result<(), CryptoImageError> { // Changed return type
    let input_encrypted_path = input_encrypted_path_ref.as_ref();
    let input_extension = input_encrypted_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

    let encrypted_file_data_payload: Vec<u8>;

    // Determine input format and extract raw payload.
    if input_extension == "txt" {
        // Read Base64 encoded data from .txt file.
        let encrypted_file_content = fs::read_to_string(input_encrypted_path)?; // Uses From<std::io::Error>
        encrypted_file_data_payload = general_purpose::STANDARD.decode(encrypted_file_content.trim())?; // Uses From<Base64DecodeError>
        println!("Decrypting from Base64 TXT file: {:?}", input_encrypted_path);
    } else if input_extension == "png" {
        // Extract embedded data from steganographic PNG file.
        let carrier_image = image::open(input_encrypted_path)?; // Uses From<ImgError>
        let (width, height) = carrier_image.dimensions();
        
        let mut extracted_bytes_buffer = Vec::new();
        let mut current_reconstructed_byte: u8 = 0;
        let mut bits_in_current_byte: u8 = 0;
        let mut bytes_extracted_count = 0;

        // Stage 1: Extract Header (5 bytes: 1 for LSB config, 4 for payload length)
        // Header is always extracted using 1 LSB per channel.
        let lsb_bits_for_header: u8 = 1;
        let data_extract_mask_header: u8 = (1 << lsb_bits_for_header) - 1;
        let header_len_bytes: usize = 5;
        
        println!("Attempting to extract steganography header ({} bytes using {} LSB/channel)...", header_len_bytes, lsb_bits_for_header);

        'header_extraction_loop: for y in 0..height {
            for x in 0..width {
                let pixel_channels = carrier_image.get_pixel(x,y).0;
                for &channel_value in pixel_channels.iter().take(3) {
                    for bit_k in 0..lsb_bits_for_header {
                        let current_extracted_bit = (channel_value >> bit_k) & data_extract_mask_header; // Mask ensures we only consider relevant bits if lsb_bits_for_header > 1, though it's 1 here.
                                                                                                    // For LSB=1, (val >> 0) & 1 is just val & 1.
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
                    } // Closes `for bit_k` loop
                    if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
                } // <<< This closing brace was missing for the `for &channel_value` loop
                 if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
            }
             if bytes_extracted_count == header_len_bytes { break 'header_extraction_loop; }
        }

        if bytes_extracted_count < header_len_bytes {
            return Err(CryptoImageError::Steganography( // Changed
                format!("Steganography PNG too small to extract full header. Expected {} bytes, got {}.", header_len_bytes, bytes_extracted_count),
            ));
        }
        
        let lsb_bits_for_payload = extracted_bytes_buffer[0];
        if !(1..=4).contains(&lsb_bits_for_payload) {
            return Err(CryptoImageError::Steganography( // Changed
                format!("Invalid LSB configuration in steganography header: {} (must be 1-4).", lsb_bits_for_payload),
            ));
        }

        let payload_len_arr: [u8; 4] = extracted_bytes_buffer[1..5].try_into()
            .map_err(|_| CryptoImageError::Steganography("Failed to convert extracted payload length bytes.".to_string()))?; // Changed
        let payload_len = u32::from_be_bytes(payload_len_arr) as usize;
        
        println!("Header extracted: LSBs for payload = {}, Payload length = {}. Attempting to extract payload...", lsb_bits_for_payload, payload_len);

        // Stage 2: Extract Payload
        // current_reconstructed_byte and bits_in_current_byte are already reset or hold partial bits from header extraction's end.
        // We need to know the exact pixel and channel where header extraction stopped.
        // For simplicity, we restart pixel iteration but skip pixels already processed for header.
        // This is inefficient. A better way is to continue from the exact bit position.

        // Let's refine to continue from the exact position.
        // We need to track current x, y, channel_idx from header loop.
        // The previous loop structure is better: iterate pixels, and inside, decide if extracting header or payload.
        // Re-doing extraction loop structure:

        let mut all_extracted_data_bytes = Vec::new();
        current_reconstructed_byte = 0; // Reset for clarity, though might carry over if header extraction didn't end on a byte boundary.
        bits_in_current_byte = 0;       // This is critical.
        bytes_extracted_count = 0;      // Counts bytes for the current stage (header then payload)

        let mut lsb_config_for_payload_opt: Option<u8> = None;
        let mut actual_payload_len_opt: Option<usize> = None;
        let mut extracting_header_stage = true;
        
        // Calculate starting pixel/channel for payload if we were to optimize.
        // For now, a single loop that changes behavior.

        'full_extraction_loop: for y_img in 0..height {
            for x_img in 0..width {
                let pixel_channels_val = carrier_image.get_pixel(x_img, y_img).0;
                for &channel_val_pix in pixel_channels_val.iter().take(3) { // Changed from range loop
                    let lsb_to_use_now = if extracting_header_stage { // Initialized directly
                        lsb_bits_for_header
                    } else {
                        lsb_config_for_payload_opt.unwrap_or(1) // Should be set
                    };

                    // let channel_val_pix = pixel_channels_val[channel_idx_val]; // Removed, loop var is now channel_val_pix
                    for bit_k_idx in 0..lsb_to_use_now {
                        let current_extracted_bit = (channel_val_pix >> bit_k_idx) & 1; // Always extract one bit at a time from LSBs
                        current_reconstructed_byte |= current_extracted_bit << bits_in_current_byte;
                        bits_in_current_byte += 1;

                        if bits_in_current_byte == 8 {
                            all_extracted_data_bytes.push(current_reconstructed_byte);
                            bytes_extracted_count += 1; // This counts bytes for the current stage
                            current_reconstructed_byte = 0;
                            bits_in_current_byte = 0;

                            if extracting_header_stage && bytes_extracted_count == header_len_bytes {
                                // Header fully extracted
                                let lsb_val = all_extracted_data_bytes[0];
                                if !(1..=4).contains(&lsb_val) {
                                     return Err(CryptoImageError::Steganography( // Changed
                                        format!("Invalid LSB config in header: {}", lsb_val)));
                                }
                                lsb_config_for_payload_opt = Some(lsb_val);

                                let len_arr_payload: [u8; 4] = all_extracted_data_bytes[1..5].try_into().unwrap();
                                actual_payload_len_opt = Some(u32::from_be_bytes(len_arr_payload) as usize);
                                
                                println!("Steg Header Decoded: LSBs for payload: {}, Payload length: {}", lsb_val, actual_payload_len_opt.unwrap());

                                extracting_header_stage = false;
                                bytes_extracted_count = 0; // Reset for payload byte count
                                all_extracted_data_bytes.clear(); // Clear buffer, it was for header

                                if actual_payload_len_opt.unwrap() == 0 {
                                    break 'full_extraction_loop; // No payload to extract
                                }
                            } else if !extracting_header_stage &&
                                      actual_payload_len_opt == Some(bytes_extracted_count)
                            {
                                // Payload fully extracted
                                break 'full_extraction_loop;
                            }
                        }
                    }
                     // Check after each channel if done
                    if !extracting_header_stage &&
                       actual_payload_len_opt.is_some_and(|len_val|
                           bytes_extracted_count == len_val && (bytes_extracted_count > 0 || len_val == 0)
                       )
                    {
                        break 'full_extraction_loop;
                    }
                }
                // Check after each pixel if done
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
            return Err(CryptoImageError::Steganography( // Changed
                "Failed to extract steganography header or determine payload parameters.".to_string(),
            ));
        }
        
        let final_payload_len = actual_payload_len_opt.unwrap();
        if all_extracted_data_bytes.len() < final_payload_len {
             return Err(CryptoImageError::Steganography( // Changed
                format!("Steganography PNG data incomplete. Expected {} payload bytes, extracted {}.", final_payload_len, all_extracted_data_bytes.len()),
            ));
        }
        
        encrypted_file_data_payload = all_extracted_data_bytes; // These are the actual payload bytes
        println!("Decrypting from Steganography PNG file (LSB {}): {:?}", lsb_config_for_payload_opt.unwrap(), input_encrypted_path);

    } else {
        return Err(CryptoImageError::InvalidParameter( // Changed
            format!("Unsupported input file type for decryption: .{}", input_extension)
        ));
    }

    // Validate payload length.
    if encrypted_file_data_payload.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(CryptoImageError::Decryption("Extracted encrypted data is too short".to_string())); // Changed
    }
    // Split the payload into salt, nonce, and ciphertext.
    let (salt_string_bytes, rest) = encrypted_file_data_payload.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    // Convert salt bytes (which are Base64 string representation) back to SaltString.
    let salt_str = std::str::from_utf8(salt_string_bytes)?; // Uses From<std::str::Utf8Error>
    let salt = SaltString::from_b64(salt_str)?; // Uses From<PasswordHashError>

    // Derive the decryption key using the extracted salt and user's secret.
    let derived_key = derive_encryption_key_with_salt(secret, &salt)?; // Changed

    // Initialize AES-256-GCM cipher.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    // Decrypt the ciphertext.
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoImageError::Decryption("AEAD decryption failed (possibly wrong secret or corrupted file)".to_string()))?; // Changed
    
    let output_decrypted_path_base_buf = PathBuf::from(output_decrypted_path_base.as_ref());

    // Attempt to detect the file format of the decrypted data and save with the correct extension.
    if let Some(format) = detect_file_format(&decrypted_data) {
        let final_output_path = output_decrypted_path_base_buf.with_extension(format);
        println!("Detected file format: {:?}. Saving decrypted file to: {:?}", format, final_output_path);
        fs::write(&final_output_path, decrypted_data)
            .map_err(CryptoImageError::Io)?;
    } else {
        eprintln!("Warning: Could not detect file format. Saving decrypted data as is to: {:?}", output_decrypted_path_base_buf);
        fs::write(&output_decrypted_path_base_buf, decrypted_data)
            .map_err(CryptoImageError::Io)?;
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
pub fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> Result<[u8; 32], CryptoImageError> { // Changed return type
    // Use Argon2id (default for Argon2 crate).
    let argon2 = Argon2::default();

    // Hash the password with the salt.
    let password_hash = argon2
        .hash_password(secret.as_bytes(), salt)?; // Uses From<Argon2Error>

    // Extract the raw hash output.
    let derived_key_output = password_hash.hash.ok_or_else(|| CryptoImageError::Encryption("Argon2 password hash output is unexpectedly None".to_string()))?;
    let key_bytes = derived_key_output.as_bytes();

    // Argon2 output can be longer than 32 bytes depending on params; we take the first 32 bytes for AES-256.
    key_bytes[..32].try_into().map_err(CryptoImageError::from) // Explicitly map TryFromSliceError
}

/// Validates the complexity of a given password.
///
/// # Arguments
/// * `password` - The password string to validate.
///
/// # Returns
/// * `true` if the password meets all complexity requirements.
/// * `false` otherwise, and prints an error message.
pub fn validate_password_complexity(password: &str) -> Result<(), CryptoImageError> {
    // Check minimum length.
    if password.len() < 16 {
        return Err(CryptoImageError::PasswordComplexity("Password must be at least 16 characters long.".to_string()));
    }
    // Check for character types.
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_ascii_alphanumeric());

    if !has_uppercase {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one uppercase letter.".to_string()));
    }
    if !has_lowercase {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one lowercase letter.".to_string()));
    }
    if !has_digit {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one digit.".to_string()));
    }
    if !has_symbol {
        return Err(CryptoImageError::PasswordComplexity("Password must contain at least one symbol (e.g., !@#$%^&*).".to_string()));
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir; // For creating temporary directories for tests

    // Helper function to create a dummy PNG file for testing base image functionality.
    fn create_dummy_png(path: &Path, width: u32, height: u32) -> Result<(), CryptoImageError> { // Changed return type
        let mut img = RgbImage::new(width, height);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([random::<u8>(), random::<u8>(), random::<u8>()]);
        }
        img.save_with_format(path, image::ImageFormat::Png)?; // Uses From<ImgError>, qualified ImageFormat
        Ok(())
    }

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let secret = "test_password";
        let salt = SaltString::from_b64("gIq+kM3PS2s7gKbtLgGjGA").unwrap(); // Fixed salt for testing

        let key1 = derive_encryption_key_with_salt(secret, &salt).unwrap(); // Updated to unwrap Result
        let key2 = derive_encryption_key_with_salt(secret, &salt).unwrap(); // Updated to unwrap Result

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
        // or with a common one if detect_file_format returns None.
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
        let original_png_width = 20; // Increased size slightly for more bits
        let original_png_height = 10;
        create_dummy_png(&input_image_path, original_png_width, original_png_height)?;
        let original_data = fs::read(&input_image_path)?;

        let secret = Zeroizing::new("anotherStrongPassword!$5^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 2; // Use 2 LSBs to test new logic

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
        let data_to_encrypt = b"A bit longer payload for steganography with base image to ensure multiple pixels are used with multi-LSB.";
        fs::write(&input_image_path, data_to_encrypt)?;
        
        // Create a base PNG image
        create_dummy_png(&base_image_path, 30, 30)?; // Ensure it's large enough

        let secret = Zeroizing::new("passwordForStegWithBase123$%^".to_string());
        let output_format_preference = "png";
        let lsb_bits: u8 = 3; // Use 3 LSBs to test new logic

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
        assert!(validate_password_complexity("ValidPass123!@#$").is_ok()); // Changed: Added '$' to make length 16
        assert!(validate_password_complexity("Another_Good-Password456$").is_ok());
    }

    #[test]
    fn test_validate_password_complexity_too_short() {
        match validate_password_complexity("Short1!") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must be at least 16 characters long.");
            }
            _ => panic!("Expected PasswordComplexity error for short password."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_uppercase() {
        match validate_password_complexity("nouppercase123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one uppercase letter.");
            }
            _ => panic!("Expected PasswordComplexity error for no uppercase."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_lowercase() {
        match validate_password_complexity("NOLOWERCASE123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one lowercase letter.");
            }
            _ => panic!("Expected PasswordComplexity error for no lowercase."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_digit() {
        match validate_password_complexity("NoDigitPassword!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one digit.");
            }
            _ => panic!("Expected PasswordComplexity error for no digit."),
        }
    }

    #[test]
    fn test_validate_password_complexity_no_symbol() {
        match validate_password_complexity("NoSymbolPassword123") {
            Err(CryptoImageError::PasswordComplexity(msg)) => {
                assert_eq!(msg, "Password must contain at least one symbol (e.g., !@#$%^&*).");
            }
            _ => panic!("Expected PasswordComplexity error for no symbol."),
        }
    }

    #[test]
    fn test_validate_password_complexity_all_criteria_missing_sequentially() {
        // Too short
        match validate_password_complexity("Pass1!") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must be at least 16 characters long."),
            _ => panic!("Test failed: too_short"),
        }
        // Missing uppercase
        match validate_password_complexity("validpass123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one uppercase letter."),
            _ => panic!("Test failed: no_uppercase"),
        }
        // Missing lowercase
        match validate_password_complexity("VALIDPASS123!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one lowercase letter."),
            _ => panic!("Test failed: no_lowercase"),
        }
        // Missing digit
        match validate_password_complexity("ValidPassword!@#") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one digit."),
            _ => panic!("Test failed: no_digit"),
        }
        // Missing symbol
        match validate_password_complexity("ValidPassword123") {
            Err(CryptoImageError::PasswordComplexity(msg)) => assert_eq!(msg, "Password must contain at least one symbol (e.g., !@#$%^&*)."),
            _ => panic!("Test failed: no_symbol"),
        }
    }
}
