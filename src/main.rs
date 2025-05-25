use aes::Aes256;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use image::{io::Reader as ImageReader, ImageError, ImageFormat, ImageOutputFormat};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Cursor, Write}, path::Path};
use clap::{Arg, ArgAction, Command};
use rpassword::read_password;
use base64::{engine::general_purpose, Engine};

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
    if original_format == "png" {
        img.write_to(&mut img_byte_array, ImageOutputFormat::Png)?;
    } else if original_format == "bmp"  {
        img.write_to(&mut img_byte_array, ImageFormat::Bmp)?;
    } else if original_format == "jpeg" || original_format == "jpg" {
        img.write_to(&mut img_byte_array, ImageOutputFormat::Jpeg(100))?;
    } else {
        return Err(ImageError::Unsupported(image::error::UnsupportedError::from_format_and_kind(
            image::error::ImageFormatHint::Unknown,
            image::error::UnsupportedErrorKind::GenericFeature("Unsupported image format".to_string()),
        )));
    }
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

    // Encode the encrypted data in Base64
    let base64_encoded = general_purpose::STANDARD.encode(output_bytes);
    fs::write(&output_encrypted_path, base64_encoded)?;
    println!("Image encrypted successfully to: {:?}", output_encrypted_path);
    Ok(original_format)
}

fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path: P,
    output_decrypted_path: P,
    key: &[u8; 32],
) -> Result<(), ImageError> {
    // Read the Base64-encoded encrypted data
    let base64_encoded_data = fs::read_to_string(&input_encrypted_path)?;
    let full_encrypted_data = general_purpose::STANDARD.decode(base64_encoded_data).map_err(|_| {
        ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Failed to decode Base64 data".to_string(),
        ))
    })?;

    let (iv_bytes, encrypted_data) = full_encrypted_data.split_at(16);

    let cipher = Aes256CbcDec::new(key.into(), iv_bytes.into());
    let mut encrypted_data_mut = encrypted_data.to_vec();
    let decrypted_data = cipher.decrypt_padded_mut::<Pkcs7>(&mut encrypted_data_mut).map_err(|_| {
        ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Failed to decrypt data".to_string(),
        ))
    })?;

    if let Some(format) = detect_file_format(decrypted_data) {
        let output_path = output_decrypted_path.as_ref().with_extension(format);
        println!("Detected file format: {:?}", format);

        let img_format = match format {
            "jpeg" => ImageFormat::Jpeg,
            "png" => ImageFormat::Png,
            "bmp" => ImageFormat::Bmp,
            _ => return Err(ImageError::Unsupported(image::error::UnsupportedError::from_format_and_kind(
                image::error::ImageFormatHint::Unknown,
                image::error::UnsupportedErrorKind::GenericFeature("Unsupported image format".to_string()),
            ))),
        };

        let img = ImageReader::with_format(Cursor::new(decrypted_data), img_format) // Use associated function
            .decode()?;
        img.save(&output_path)?;
        println!("Image decrypted successfully to: {:?}", output_path);
    } else {
        eprintln!("Warning: Could not detect file format. Saving as is.");
        let output_path = output_decrypted_path.as_ref();
        fs::write(&output_path, decrypted_data)?;
        println!("Image decrypted successfully to: {:?}", output_path);
    }

    Ok(())
}

fn detect_file_format(decrypted_data: &[u8]) -> Option<&'static str> {
    if decrypted_data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if decrypted_data.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if decrypted_data.starts_with(&[b'B', b'M']) {
        Some("bmp")
    } else {
        None
    }
}

fn derive_encryption_key(secret: &str) -> [u8; 32] {
    // Ensure the hash result is exactly 32 bytes
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let hash_result = hasher.finalize();
    hash_result[..32].try_into().expect("Hash result should be 32 bytes")
}

fn main() {
    // Define CLI arguments using `clap`
    let matches = Command::new("PixelLock")
        .version("1.0")
        .author("Saltuk Alakus")
        .about("Encrypts and decrypts images in JPEG, PNG, or BMP using AES-256-CBC")
        .arg(
            Arg::new("decrypt")
                .short('d')
                .long("decrypt")
                .action(ArgAction::SetTrue)
                .help("Decrypt the input file"),
        )
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .action(ArgAction::SetTrue)
                .help("Encrypt the input file"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the input file"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the output file"),
        )
        .get_matches();

    // Determine mode (encrypt or decrypt)
    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");

    if is_decrypt == is_encrypt {
        eprintln!("Error: You must specify either --encrypt (-e) or --decrypt (-d).");
        return;
    }

    let input_file = matches.get_one::<String>("input").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();

    println!("Current working directory: {:?}", std::env::current_dir().unwrap());
    if !Path::new(input_file).exists() {
        eprintln!("Error: Input file '{}' not found.", input_file);
        return;
    }

    // Prompt the user for the secret twice
    print!("Enter your secret: ");
    io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
    let secret1 = read_password().expect("Failed to read secret");

    print!("Re-enter your secret: ");
    io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
    let secret2 = read_password().expect("Failed to read secret");

    // Validate that both secrets match
    if secret1 != secret2 {
        eprintln!("Error: Secrets do not match. Please try again.");
        return;
    }

    let encryption_key_bytes = derive_encryption_key(&secret1);

    if is_encrypt {
        match encrypt_image(input_file, output_file, &encryption_key_bytes) {
            Ok(original_format) => {
                println!("File encrypted successfully. Original format: {}", original_format);
            }
            Err(e) => {
                eprintln!("Error encrypting file: {}", e);
            }
        }
    } else if is_decrypt {
        if let Err(e) = decrypt_image(input_file, output_file, &encryption_key_bytes) {
            eprintln!("Error decrypting file: {}", e);
        }
    }
}