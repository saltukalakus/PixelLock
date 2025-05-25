use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, KeyInit}; 
use image::{io::Reader as ImageReader, ImageError, ImageFormat, ImageOutputFormat};
use rand::{rngs::OsRng, Rng}; 
use std::{fs, io::{self, Cursor, Write}, path::Path};
use clap::{Arg, ArgAction, Command};
use rpassword::read_password;
use argon2::{Argon2, PasswordHasher}; 
use argon2::password_hash::{SaltString};

const SALT_STRING_LEN: usize = 22; 
const NONCE_STRING_LEN: usize = 12; // Nonce length for AES-GCM

fn encrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P,
    output_encrypted_path: P,
    secret: &str,
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
    } else if original_format == "bmp" {
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

    let salt: SaltString = SaltString::generate(&mut OsRng); // Generate a random salt
    let derived_key = derive_encryption_key_with_salt(secret, &salt); // Derive key using this salt

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce_bytes: [u8; NONCE_STRING_LEN] = OsRng.gen(); // Generate a 96-bit nonce
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data = cipher.encrypt(nonce, img_bytes.as_ref())
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encryption failed".to_string(),
        )))?;

    let salt_bytes_to_store = salt.as_bytes(); // These are 22 bytes for a 16-byte raw salt B64Unpadded
    assert_eq!(salt_bytes_to_store.len(), SALT_STRING_LEN, "Generated salt string length does not match expected SALT_STRING_LEN.");

    let mut output_bytes = Vec::new();
    output_bytes.extend_from_slice(salt_bytes_to_store); // Store the salt string bytes
    output_bytes.extend_from_slice(&nonce_bytes); // Store the nonce
    output_bytes.extend_from_slice(&encrypted_data);

    fs::write(&output_encrypted_path, output_bytes)?;
    println!("Image encrypted successfully to: {:?}", output_encrypted_path);
    Ok(original_format)
}

fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path: P,
    output_decrypted_path: P,
    secret: &str, 
) -> Result<(), ImageError> {
    let encrypted_file_data = fs::read(&input_encrypted_path)?;
    if encrypted_file_data.len() < SALT_STRING_LEN + NONCE_STRING_LEN {
        return Err(ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Encrypted file is too short".to_string(),
        )));
    }
    let (salt_string_bytes, rest) = encrypted_file_data.split_at(SALT_STRING_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_STRING_LEN);

    let salt_str = std::str::from_utf8(salt_string_bytes).map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, "Invalid salt UTF-8".to_string()
    )))?;
    let salt = SaltString::new(salt_str).map_err(|e| ImageError::Decoding(image::error::DecodingError::new(
        image::error::ImageFormatHint::Unknown, format!("Invalid salt format: {}", e)
    )))?;

    let derived_key = derive_encryption_key_with_salt(secret, &salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| ImageError::Decoding(image::error::DecodingError::new(
            image::error::ImageFormatHint::Unknown,
            "Decryption failed (possibly wrong secret or corrupted file)".to_string(),
        )))?;

    if let Some(format) = detect_file_format(&decrypted_data) {
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

        let img = ImageReader::with_format(Cursor::new(decrypted_data), img_format)
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

fn derive_encryption_key_with_salt(secret: &str, salt: &SaltString) -> [u8; 32] {
    let argon2 = Argon2::default(); // Use the default Argon2 configuration

    let password_hash = argon2
        .hash_password(secret.as_bytes(), salt)
        .expect("Failed to hash password");

    let derived_key = password_hash.hash.expect("Hash missing in password hash");
    let key_bytes = derived_key.as_bytes();

    key_bytes[..32].try_into().expect("Derived key should be 32 bytes")
}

fn validate_password_complexity(password: &str) -> bool {
    if password.len() < 16 {
        eprintln!("Error: Password must be at least 16 characters long.");
        return false;
    }
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_ascii_alphanumeric());

    if !has_uppercase {
        eprintln!("Error: Password must contain at least one uppercase letter.");
        return false;
    }
    if !has_lowercase {
        eprintln!("Error: Password must contain at least one lowercase letter.");
        return false;
    }
    if !has_digit {
        eprintln!("Error: Password must contain at least one digit.");
        return false;
    }
    if !has_symbol {
        eprintln!("Error: Password must contain at least one symbol (e.g., !@#$%^&*).");
        return false;
    }
    true
}

fn prompt_and_validate_secret() -> String {
    loop {
        print!("Enter your secret: ");
        io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
        let secret1 = read_password().expect("Failed to read secret");

        if !validate_password_complexity(&secret1) {
            // Error messages are printed by validate_password_complexity
            // Ask to re-enter without exiting immediately, or exit if preferred.
            // For now, let's allow re-entry.
            println!("Please try again, ensuring the password meets all complexity requirements.");
            continue;
        }

        print!("Re-enter your secret: ");
        io::stdout().flush().unwrap(); // Ensure the prompt is displayed immediately
        let secret2 = read_password().expect("Failed to read secret");

        if secret1 != secret2 {
            eprintln!("Error: Secrets do not match. Please try again.");
            continue; // Allow re-entry
        }
        return secret1; // Return the secret as a string
    }
}

fn validate_file_exists(file_path: &str) {
    if !Path::new(file_path).exists() {
        eprintln!("Error: Input file '{}' not found.", file_path);
        std::process::exit(1);
    }
}

fn main() {
    let matches = Command::new("PixelLock")
        .version("1.0")
        .author("Saltuk Alakus")
        .about("Encrypts and decrypts images in JPEG, PNG, or BMP using AES-256-GCM")
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

    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");

    if is_decrypt == is_encrypt {
        eprintln!("Error: You must specify either --encrypt (-e) or --decrypt (-d).");
        return;
    }

    let input_file = matches.get_one::<String>("input").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();

    validate_file_exists(input_file);

    let encryption_secret = prompt_and_validate_secret();

    if is_encrypt {
        match encrypt_image(input_file, output_file, &encryption_secret) {
            Ok(original_format) => {
                println!("File encrypted successfully. Original format: {}", original_format);
            }
            Err(e) => {
                eprintln!("Error encrypting file: {}", e);
            }
        }
    } else if is_decrypt {
        if let Err(e) = decrypt_image(input_file, output_file, &encryption_secret) {
            eprintln!("Error decrypting file: {}", e);
        }
    }
}