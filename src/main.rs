use aes::Aes256;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use image::{io::Reader as ImageReader, ImageError, ImageFormat};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Cursor, Write}, path::Path};
use clap::{Arg, ArgAction, Command};
use rpassword::read_password;

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
    // Define CLI arguments using `clap`
    let matches = Command::new("PixelLock")
        .version("1.0")
        .author("Your Name")
        .about("Encrypts and decrypts image files")
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
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(clap::value_parser!(String))
                .help("Original format of the image (required for decryption)"),
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
    let original_format = matches.get_one::<String>("format").map(|s| s.as_str()).unwrap_or("");

    if is_decrypt && original_format.is_empty() {
        eprintln!("Error: Original format is required for decryption.");
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

    let mut hasher = Sha256::new();
    hasher.update(secret1);
    let encryption_key_bytes = hasher.finalize();

    if !Path::new(input_file).exists() {
        eprintln!("Error: Input file '{}' not found.", input_file);
        return;
    }

    if is_encrypt {
        match encrypt_image(input_file, output_file, &encryption_key_bytes[..32].try_into().unwrap()) {
            Ok(original_format) => {
                println!("File encrypted successfully. Original format: {}", original_format);
            }
            Err(e) => {
                eprintln!("Error encrypting file: {}", e);
            }
        }
    } else if is_decrypt {
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
}