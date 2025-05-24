use aes::Aes256;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use image::{io::Reader as ImageReader, ImageError, ImageFormat};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Cursor, path::Path};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

fn encrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P,
    output_encrypted_path: P,
    key: &[u8; 32],
) -> Result<String, ImageError> {
    let img = ImageReader::open(&input_image_path)?.decode()?;
    let original_format = input_image_path
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("png")
        .to_string();

    let mut img_byte_array = Cursor::new(Vec::new());
    img.write_to(&mut img_byte_array, ImageFormat::Png)?;
    let img_bytes = img_byte_array.into_inner();

    let mut iv_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut iv_bytes);

    let cipher = Aes256CbcEnc::new(key.into(), &iv_bytes.into());
    let mut buffer = vec![0u8; img_bytes.len() + 16]; // Allocate buffer with padding space
    buffer[..img_bytes.len()].copy_from_slice(&img_bytes);
    let encrypted_data = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, img_bytes.len())
        .unwrap()
        .to_vec();

    let mut output_bytes = Vec::new();
    output_bytes.extend_from_slice(&iv_bytes);
    output_bytes.extend_from_slice(&encrypted_data);

    fs::write(&output_encrypted_path, output_bytes)?;
    println!("Image encrypted successfully to: {:?}", output_encrypted_path);
    Ok(original_format)
}

fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path: P,
    output_decrypted_path: P,
    key: &[u8; 32],
    original_format: &str,
) -> Result<(), ImageError> {
    let full_encrypted_data = fs::read(&input_encrypted_path)?;
    let (iv_bytes, encrypted_data) = full_encrypted_data.split_at(16);

    let cipher = Aes256CbcDec::new(key.into(), iv_bytes.into());
    let mut encrypted_data_mut = encrypted_data.to_vec();
    let decrypted_data = cipher.decrypt_padded_mut::<Pkcs7>(&mut encrypted_data_mut).map_err(|_| {
        ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Failed to decrypt data".to_string(),
        ))
    })?;

    // Use the explicitly passed original format
    let format = match ImageFormat::from_extension(original_format) {
        Some(fmt) => fmt,
        None => {
            return Err(ImageError::Decoding(image::error::DecodingError::new(
                image::error::ImageFormatHint::Unknown,
                format!("Unknown image format: {}", original_format),
            )));
        }
    };

    let img = ImageReader::new(Cursor::new(decrypted_data))
        .with_guessed_format()?
        .decode()?;
    img.save_with_format(&output_decrypted_path, format)?;

    println!("Image decrypted successfully to: {:?}", output_decrypted_path);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!(
            "Usage: {} <encrypt|decrypt> <secret-string> <input-file-path> <output-file-path> [original-format]",
            args[0]
        );
        return;
    }

    let mode = &args[1];
    let secret = &args[2];
    let input_file = &args[3];
    let output_file = &args[4];
    let original_format = if mode == "decrypt" {
        if args.len() < 6 {
            eprintln!("Error: Missing original format for decryption.");
            return;
        }
        &args[5]
    } else {
        ""
    };

    let mut hasher = Sha256::new();
    hasher.update(secret);
    let encryption_key_bytes = hasher.finalize();

    if !Path::new(input_file).exists() {
        eprintln!("Error: Input file '{}' not found.", input_file);
        return;
    }

    match mode.as_str() {
        "encrypt" => {
            match encrypt_image(input_file, output_file, &encryption_key_bytes[..32].try_into().unwrap()) {
                Ok(original_format) => {
                    println!("File encrypted successfully. Original format: {}", original_format);
                }
                Err(e) => {
                    eprintln!("Error encrypting file: {}", e);
                }
            }
        }
        "decrypt" => {
            if let Err(e) = decrypt_image(
                input_file,
                output_file,
                &encryption_key_bytes[..32].try_into().unwrap(),
                original_format,
            ) {
                eprintln!("Error decrypting file: {}", e);
            } else {
                println!("File decrypted successfully to: {}", output_file);
            }
        }
        _ => {
            eprintln!("Error: Invalid mode '{}'. Use 'encrypt' or 'decrypt'.", mode);
        }
    }
}