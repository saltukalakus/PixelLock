use std::{fs, io::{self, Write}, path::{Path}};
use clap::{Arg, ArgAction, Command}; 
use rpassword::read_password;
use zeroize::Zeroizing;
use argon2::password_hash::SaltString; // Added for generating salt in main
use rand::rngs::OsRng; // Added for SaltString::generate

mod secret; // Changed from mod utils;
mod error_types; 
mod encrypt; 
mod decrypt; 

/// Prompts the user for a secret (password) and validates it if in encryption mode.
/// Uses `Zeroizing` to ensure the secret is cleared from memory when no longer needed.
///
/// # Arguments
/// * `is_encryption_mode` - `true` if called during encryption (requires confirmation and complexity check),
///   `false` if called during decryption (prompts once).
///
/// # Returns
/// * A `Zeroizing<String>` containing the user's secret.
fn prompt_and_validate_secret(is_encryption_mode: bool) -> Zeroizing<String> {
    if is_encryption_mode { // Removed parentheses
        // Encryption mode: prompt for new secret, validate complexity, and confirm.
        loop {
            print!("Enter your new secret: ");
            io::stdout().flush().unwrap();
            let secret1_plain = read_password().expect("Failed to read secret");

            // Validate complexity for new secrets.
            match secret::validate_password_complexity(&secret1_plain) { // Changed from utils::
                Ok(_) => { /* Password is complex enough */ }
                Err(e) => {
                    eprintln!("Error: {}", e); // Print the specific complexity error
                    println!("Please try again, ensuring the password meets all complexity requirements.");
                    continue;
                }
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

/// Validates if a given file path exists. Exits the program if it doesn't.
///
/// # Arguments
/// * `file_path` - The path string of the file to check.
fn validate_file_exists(file_path: &str) {
    if !Path::new(file_path).exists() {
        eprintln!("Error: Input file '{}' not found.", file_path);
        std::process::exit(1);
    }
}

/// Builds the command-line interface configuration using `clap`.
/// Defines all available arguments, options, and help messages.
///
/// # Returns
/// * `Command` object for further processing (e.g., getting matches).
fn build_cli_command() -> Command { // Renamed and changed return type
    Command::new("PixelLock")
        .version("1.0")
        .author("Saltuk Alakus")
        .about("\nPixelLock is a command-line tool to secure your pictures with military-grade encryption. 
                \nIt helps enhance privacy and provide an additional layer of security while storing images.")
        // Mode arguments: encrypt or decrypt.
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
        // Input/Output path arguments.
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the input file or folder. If -i is a folder, processes all supported files in that folder and -o must be an output folder."),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the output file or folder"),
        )
        // Encryption-specific arguments.
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(["txt", "png"])
                .default_value("png")
                .help("Output format for encryption: 'png' (steganography) or 'txt' (Base64). Only affects encryption."),
        )
        .arg(
            Arg::new("base")
                .short('b')
                .long("base")
                .value_parser(clap::value_parser!(String))
                .required(false)
                .help("Path to a base PNG image to use for steganography when format is 'png'. If too small, it will be tiled to fit data.")
        )
        .arg(
            Arg::new("ratio")
                .short('r')
                .long("ratio")
                .value_parser(clap::value_parser!(u8).range(1..=4)) // Expects 1, 2, 3, or 4
                .default_value("1")
                .required(false)
                .help("LSB ratio (1-4) for steganography when using a base image (-b). Higher means more data per pixel.")
        )
}

/// Processes all supported files in an input directory for encryption or decryption.
///
/// # Arguments
/// * `input_dir_str` - Path to the input directory.
/// * `output_dir_str` - Path to the output directory.
/// * `is_encrypt` - `true` for encryption mode, `false` for decryption mode.
/// * `secret_or_key_salt` - Either the user's secret (for decryption) or pre-derived key and salt (for encryption).
/// * `output_format_preference` - Preferred output format for encryption ("txt" or "png").
/// * `base_image_path_str_opt` - Optional path to a base image for steganography.
/// * `lsb_bits_for_encryption` - LSB bits to use per channel for steganographic encryption.
fn process_folder_mode(
    input_dir_str: &str, 
    output_dir_str: &str, 
    is_encrypt: bool, 
    // For encryption: derived_key and salt_for_payload. For decryption: secret.
    // We'll pass them separately for type safety in the call.
    // Let's adjust the parameters based on `is_encrypt` before calling, or use an enum.
    // For simplicity, we'll adjust parameters in main and pass what's needed.
    // So, for encryption, this will receive derived_key and salt_for_payload.
    // For decryption, it will receive the secret.
    // This means the function signature needs to be more flexible or we need two versions.
    // Let's pass what's needed directly.
    secret_for_decryption: Option<&Zeroizing<String>>, // Only for decryption
    derived_key_for_encryption: Option<&[u8; 32]>, // Only for encryption
    salt_for_encryption_payload: Option<&SaltString>, // Only for encryption
    output_format_preference: &str, 
    base_image_path_str_opt: Option<&String>, 
    lsb_bits_for_encryption: u8
) {
    let input_dir = Path::new(input_dir_str);

    // Ensure output directory exists or create it.
    let output_dir = Path::new(output_dir_str);

    // Ensure output directory exists or create it.
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

    // Read directory entries.
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
                            // Determine if the file should be processed based on its extension and current mode.
                            let extension = current_input_file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
                            let lower_extension = extension.to_lowercase();

                            let should_process = if is_encrypt {
                                // Supported extensions for encryption input.
                                let supported_encryption_extensions = ["jpeg", "jpg", "bmp", "png", "gif", "tiff", "tif", "webp"];
                                supported_encryption_extensions.contains(&lower_extension.as_str())
                            } else {
                                // Supported extensions for decryption input.
                                lower_extension == "txt" || lower_extension == "png"
                            };

                            if !should_process {
                                files_skipped_extension += 1;
                                continue; // Skip unsupported files.
                            }

                            // Construct the output file path.
                            let file_name_os_str = current_input_file_path.file_name().unwrap_or_default();

                            let current_output_file_path_base = if is_encrypt {
                                // For encryption, output name is input_filename.original_ext.encrypted
                                // to ensure uniqueness if original extensions differ but stems are same,
                                // or if different files have the same stem.
                                // The final extension (.png or .txt) will be added by encrypt_image.
                                let input_filename_complete_str = file_name_os_str.to_string_lossy();
                                let new_base_name = format!("{}.encrypted", input_filename_complete_str);
                                output_dir.join(new_base_name)
                            } else {
                                // For decryption, output name is input stem, extension auto-detected.
                                let stem = current_input_file_path.file_stem().unwrap_or_else(|| std::ffi::OsStr::new("decrypted_file"));
                                output_dir.join(stem)
                            };

                            print!("Processing {:?} -> {:?} (final extension will be .{} or auto-detected) ... ", 
                                   current_input_file_path, 
                                   current_output_file_path_base, 
                                   if is_encrypt { output_format_preference } else { "auto" });

                            // Perform encryption or decryption.
                            let operation_result = if is_encrypt {
                                // Ensure derived_key and salt_for_payload are available for encryption
                                let key = derived_key_for_encryption.expect("Derived key missing for folder encryption");
                                let salt = salt_for_encryption_payload.expect("Salt for payload missing for folder encryption");
                                encrypt::encrypt_image_core( // Call encrypt_image_core
                                    &current_input_file_path, 
                                    &current_output_file_path_base, 
                                    key, 
                                    salt, 
                                    output_format_preference, 
                                    base_image_path_str_opt.map(Path::new), 
                                    lsb_bits_for_encryption
                                ).map(|_| ())
                            } else {
                                let secret = secret_for_decryption.expect("Secret missing for folder decryption");
                                decrypt::decrypt_image(&current_input_file_path, &current_output_file_path_base, secret)
                            };

                            match operation_result {
                                Ok(_) => {
                                    // Message is printed by encrypt_image/decrypt_image or the print! above
                                    // For successful decryption, the success message is in decrypt_image.
                                    // For successful encryption, it's in encrypt_image.
                                    // We add a simple "Done." here for folder mode.
                                    println!("Done.");
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
            eprintln!("Error: Could not read input directory '{}': {}", input_dir_str, e);
            std::process::exit(1);
        }
    }
}

/// Main function: parses CLI arguments, validates them, prompts for secret,
/// and dispatches to either single file processing or folder processing mode.
fn main() {
    // Parse command-line arguments.
    let matches = build_cli_command().get_matches(); // Call get_matches here

    // Extract operation mode and format preferences.
    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");
    let output_format_preference = matches.get_one::<String>("format").unwrap().as_str();
    let base_image_path_str_opt = matches.get_one::<String>("base");
    
    let ratio_from_cli = *matches.get_one::<u8>("ratio").unwrap(); 
    let user_explicitly_set_ratio = matches.value_source("ratio") == Some(clap::parser::ValueSource::CommandLine);

    // Validate argument combinations.
    if is_decrypt {
        // Decryption mode should not have encryption-specific options.
        if base_image_path_str_opt.is_some() {
            eprintln!("Error: --base (-b) option cannot be used with decryption mode (-d).");
            std::process::exit(1);
        }
        if user_explicitly_set_ratio {
            eprintln!("Error: --ratio (-r) option cannot be used with decryption mode (-d).");
            std::process::exit(1);
        }
    } else if output_format_preference == "txt" {
        // "txt" format does not support steganography options.
        if base_image_path_str_opt.is_some() {
            eprintln!("Error: --base (-b) option can only be used with --format png.");
            std::process::exit(1);
        }
        if user_explicitly_set_ratio {
            eprintln!("Error: --ratio (-r) option can only be used with --format png.");
            std::process::exit(1);
        }
    } else if user_explicitly_set_ratio && base_image_path_str_opt.is_none() {
        // Ratio requires a base image.
        eprintln!("Error: --ratio (-r) option requires a base image to be specified with --base (-b) when using --format png.");
        std::process::exit(1);
    }

    // Determine LSB bits for encryption based on settings.
    let lsb_bits_for_encryption = if output_format_preference == "png" {
        if base_image_path_str_opt.is_some() {
            ratio_from_cli // Use user-specified ratio (1-4) if base image is provided.
        } else {
            // No base image (new image generated), use "full 8-bit" embedding.
            8 
        }
    } else {
        1 // Default for non-PNG or non-steganography scenarios (though not directly used for .txt).
    };

    // Ensure either encrypt or decrypt mode is chosen, but not both.
    if is_decrypt == is_encrypt {
        eprintln!("Error: You must specify either --encrypt (-e) or --decrypt (-d).");
        std::process::exit(1);
    }

    // Get input and output paths.
    let input_arg_str = matches.get_one::<String>("input").unwrap();
    let output_arg_str = matches.get_one::<String>("output").unwrap();

    let input_path = Path::new(input_arg_str);

    // Prompt for and validate the secret.
    let encryption_secret: Zeroizing<String> = prompt_and_validate_secret(is_encrypt);

    // Dispatch to folder or single file processing.
    if input_path.is_dir() {
        // Input is a directory, process in folder mode.
        let output_path = Path::new(output_arg_str);
        if output_path.exists() && !output_path.is_dir() {
            eprintln!("Error: Input is a folder, so output '{}' must also be a folder or not exist (it will be created). It currently exists as a file.", output_arg_str);
            std::process::exit(1);
        }

        if is_encrypt {
            let salt_for_folder = SaltString::generate(&mut OsRng);
            match secret::derive_encryption_key_with_salt(&encryption_secret, &salt_for_folder) { // Changed from utils::
                Ok(derived_key) => {
                    process_folder_mode(
                        input_arg_str, 
                        output_arg_str, 
                        is_encrypt, 
                        None, // secret_for_decryption
                        Some(&derived_key), // derived_key_for_encryption
                        Some(&salt_for_folder), // salt_for_encryption_payload
                        output_format_preference, 
                        base_image_path_str_opt, 
                        lsb_bits_for_encryption
                    );
                }
                Err(e) => {
                    eprintln!("Error deriving key for folder encryption: {}", e);
                    std::process::exit(1);
                }
            }
        } else { // Decryption mode for folder
            process_folder_mode(
                input_arg_str, 
                output_arg_str, 
                is_encrypt, 
                Some(&encryption_secret), // secret_for_decryption
                None, // derived_key_for_encryption
                None, // salt_for_encryption_payload
                output_format_preference, // Not used in decryption path of process_folder_mode
                base_image_path_str_opt,  // Not used
                lsb_bits_for_encryption   // Not used
            );
        }
    } else {
        // Input is a single file.
        validate_file_exists(input_arg_str); // Ensure input file exists.
        if is_encrypt {
            match encrypt::encrypt_image(input_arg_str, output_arg_str, &encryption_secret, output_format_preference, base_image_path_str_opt.map(Path::new), lsb_bits_for_encryption) {
                Ok(_original_format) => { /* Success message printed by encrypt_image */ } 
                Err(e) => {
                    eprintln!("Error encrypting file: {}", e);
                    std::process::exit(1); // Exit on error for single file mode
                }
            }
        } else if is_decrypt {
            if let Err(e) = decrypt::decrypt_image(input_arg_str, output_arg_str, &encryption_secret) { // Updated to decrypt::
                eprintln!("Error decrypting file: {}", e);
                std::process::exit(1); // Exit on error for single file mode
            }
            // Success message is printed by decrypt_image
        }
    }
}