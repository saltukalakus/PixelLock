use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, KeyInit}; 
use image::{io::Reader as ImageReader, ImageError, ImageFormat, ImageOutputFormat};
use rand::{rngs::OsRng, Rng}; 
use std::{fs, io::{self, Cursor, Write}, path::{Path, PathBuf}};
use clap::{Arg, ArgAction, Command};
use rpassword::read_password;
use argon2::{Argon2, PasswordHasher}; 
use argon2::password_hash::{SaltString};
use zeroize::Zeroizing; // Added for secure secret handling

const SALT_STRING_LEN: usize = 22; 
const NONCE_STRING_LEN: usize = 12; // Nonce length for AES-GCM

fn encrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_image_path: P,
    output_encrypted_path_param: P, // Renamed for clarity
    secret: &Zeroizing<String>, // Changed type
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
    let derived_key = derive_encryption_key_with_salt(&*secret, &salt); // Dereference secret

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

    let output_path_buf = PathBuf::from(output_encrypted_path_param.as_ref());
    let final_output_path = output_path_buf.with_extension("txt");

    fs::write(&final_output_path, output_bytes)?;
    println!("Image encrypted successfully to: {:?}", final_output_path);
    Ok(original_format)
}

fn decrypt_image<P: AsRef<Path> + std::fmt::Debug>(
    input_encrypted_path: P,
    output_decrypted_path: P,
    secret: &Zeroizing<String>, // Changed type
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

    let derived_key = derive_encryption_key_with_salt(&*secret, &salt); // Dereference secret

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

fn prompt_and_validate_secret(is_encryption_mode: bool) -> Zeroizing<String> { // Changed return type
    if is_encryption_mode {
        loop {
            print!("Enter your new secret: ");
            io::stdout().flush().unwrap();
            let secret1_plain = read_password().expect("Failed to read secret");

            if !validate_password_complexity(&secret1_plain) {
                println!("Please try again, ensuring the password meets all complexity requirements.");
                continue;
            }

            print!("Re-enter your new secret: ");
            io::stdout().flush().unwrap();
            let secret2_plain = read_password().expect("Failed to read secret");

            if secret1_plain != secret2_plain {
                eprintln!("Error: Secrets do not match. Please try again.");
                continue;
            }
            return Zeroizing::new(secret1_plain);
        }
    } else {
        print!("Enter your secret: ");
        io::stdout().flush().unwrap();
        let secret_plain = read_password().expect("Failed to read secret");
        Zeroizing::new(secret_plain)
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
        .about("Encrypts and decrypts images in JPEG, PNG, or BMP using AES-256-GCM. \nWith -f, processes all files in a folder.")
        .arg(
            Arg::new("decrypt")
                .short('d')
                .long("decrypt")
                .action(ArgAction::SetTrue)
                .help("Decrypt the input file(s)"),
        )
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .action(ArgAction::SetTrue)
                .help("Encrypt the input file(s)"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the input file or folder (if -f is used)"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the output file or folder (if -f is used)"),
        )
        .arg(
            Arg::new("folder")
                .short('f')
                .long("folder")
                .action(ArgAction::SetTrue)
                .help("Process all files in the input folder (non-recursive). -i becomes input folder, -o becomes output folder."),
        )
        .get_matches();

    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");
    let is_folder_mode = matches.get_flag("folder");

    if is_decrypt == is_encrypt {
        eprintln!("Error: You must specify either --encrypt (-e) or --decrypt (-d).");
        std::process::exit(1);
    }

    let input_arg_str = matches.get_one::<String>("input").unwrap();
    let output_arg_str = matches.get_one::<String>("output").unwrap();

    let encryption_secret: Zeroizing<String> = prompt_and_validate_secret(is_encrypt);

    if is_folder_mode {
        let input_dir = Path::new(input_arg_str);
        let output_dir = Path::new(output_arg_str);

        if !input_dir.is_dir() {
            eprintln!("Error: Input path '{}' is not a directory. Use -f for folder operations.", input_arg_str);
            std::process::exit(1);
        }

        if !output_dir.exists() {
            if let Err(e) = fs::create_dir_all(&output_dir) {
                eprintln!("Error: Could not create output directory '{}': {}", output_arg_str, e);
                std::process::exit(1);
            }
            println!("Created output directory: {:?}", output_dir);
        } else if !output_dir.is_dir() {
            eprintln!("Error: Output path '{}' exists but is not a directory.", output_arg_str);
            std::process::exit(1);
        }

        match fs::read_dir(input_dir) {
            Ok(entries) => {
                let mut files_processed_successfully = 0;
                let mut files_failed_to_process = 0;
                let mut files_skipped_extension = 0;
                println!("\nStarting folder processing...");

                for entry_result in entries {
                    match entry_result {
                        Ok(entry) => {
                            let current_input_file_path = entry.path();
                            if current_input_file_path.is_file() {
                                let extension = current_input_file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
                                let lower_extension = extension.to_lowercase();
                                
                                if !["jpeg", "jpg", "bmp", "png"].contains(&lower_extension.as_str()) {
                                    files_skipped_extension += 1;
                                    continue;
                                }

                                let file_name = match current_input_file_path.file_name() {
                                    Some(name) => name,
                                    None => {
                                        eprintln!("Warning: Could not get file name for {:?}, skipping.", current_input_file_path);
                                        files_failed_to_process += 1;
                                        continue;
                                    }
                                };
                                let current_output_file_path = output_dir.join(file_name);

                                print!("Processing {:?} -> {:?} ... ", current_input_file_path, current_output_file_path);
                                io::stdout().flush().unwrap();

                                let operation_result = if is_encrypt {
                                    encrypt_image(&current_input_file_path, &current_output_file_path, &encryption_secret).map(|_| ())
                                } else { // is_decrypt
                                    decrypt_image(&current_input_file_path, &current_output_file_path, &encryption_secret)
                                };

                                match operation_result {
                                    Ok(_) => {
                                        files_processed_successfully += 1;
                                    }
                                    Err(e) => {
                                        eprintln!("\nError processing file {:?}: {}", current_input_file_path, e);
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
                println!("\nFolder processing summary:");
                println!("  Files successfully processed: {}", files_processed_successfully);
                println!("  Files failed to process: {}", files_failed_to_process);
                if files_skipped_extension > 0 {
                    println!("  Files skipped (unsupported extension): {}", files_skipped_extension);
                }
            }
            Err(e) => {
                eprintln!("Error: Could not read input directory '{}': {}", input_arg_str, e);
                std::process::exit(1);
            }
        }
    } else { // Single file mode
        validate_file_exists(input_arg_str);
        if is_encrypt {
            match encrypt_image(input_arg_str, output_arg_str, &encryption_secret) {
                Ok(_original_format) => {
                }
                Err(e) => {
                    eprintln!("Error encrypting file: {}", e);
                }
            }
        } else if is_decrypt {
            if let Err(e) = decrypt_image(input_arg_str, output_arg_str, &encryption_secret) {
                eprintln!("Error decrypting file: {}", e);
            }
        }
    }
}