use std::{io::{self, Write}, path::{Path}};
use clap::{Arg, ArgAction, Command}; 
use rpassword::read_password;
use zeroize::Zeroizing;

mod secret;
mod error_types; 
mod encrypt; 
mod decrypt; 

const APP_VERSION_STR: &str = env!("CARGO_PKG_VERSION");

/// Parses a version string (e.g., "1.0.0") into (major, minor, patch) u8 tuple.
fn parse_version_to_bytes(version_str: &str) -> Result<(u8, u8, u8), String> {
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("Version string '{}' is not in major.minor.patch format.", version_str));
    }
    let major = parts[0].parse::<u8>().map_err(|e| format!("Invalid major version '{}': {}", parts[0], e))?;
    let minor = parts[1].parse::<u8>().map_err(|e| format!("Invalid minor version '{}': {}", parts[1], e))?;
    let patch = parts[2].parse::<u8>().map_err(|e| format!("Invalid patch version '{}': {}", parts[2], e))?;
    Ok((major, minor, patch))
}

/// Prompts the user for a secret (password) and validates it if in encryption mode.
/// Uses `Zeroizing` to ensure the secret is cleared from memory when no longer needed.
///
/// # Arguments
/// * `is_encryption_mode` - `true` if called during encryption (requires confirmation and complexity check),
///   `false` if called during decryption (prompts once).
/// * `cli_password_opt` - An optional password string provided via CLI.
///
/// # Returns
/// * A `Zeroizing<String>` containing the user's secret.
fn prompt_and_validate_secret(is_encryption_mode: bool, cli_password_opt: Option<String>) -> Zeroizing<String> {
    if let Some(cli_password) = cli_password_opt {
        if is_encryption_mode {
            // Validate complexity for new secrets even if provided via CLI.
            match secret::validate_password_complexity(&cli_password) {
                Ok(_) => { /* Password is complex enough */ }
                Err(e) => {
                    eprintln!("Error: Password provided via -p/--password is not complex enough: {}", e);
                    eprintln!("Please ensure the password meets all complexity requirements.");
                    std::process::exit(1); // Exit if CLI password for encryption is not complex.
                }
            }
        }
        // Use the password from CLI directly.
        // No confirmation prompt needed for CLI-provided password.
        return Zeroizing::new(cli_password);
    }

    // Original interactive prompting logic if no CLI password is provided.
    if is_encryption_mode {
        // Encryption mode: prompt for new secret, validate complexity, and confirm.
        loop {
            print!("Enter your new secret: ");
            io::stdout().flush().unwrap();
            let secret1_plain = read_password().expect("Failed to read secret");

            // Validate complexity for new secrets.
            match secret::validate_password_complexity(&secret1_plain) {
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
fn build_cli_command() -> Command {
    Command::new("pixellock")
        .version(APP_VERSION_STR) // Use const for version
        .author("Saltuk Alakus")
        .about("\nPixelLock is a command-line tool to secure your files (images and other types) with military-grade encryption. 
                \nIt helps enhance privacy and provide an additional layer of security while storing your sensitive files.")
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
        // Password argument
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_parser(clap::value_parser!(String))
                .required(false)
                .help("Provide the password directly. If not set, you will be prompted interactively. Use with caution due to shell history risks.")
        )
        // Recursive flag for folder operations
        .arg(
            Arg::new("recursive")
                .short('R') // Changed from 'r' to 'R'
                .long("recursive")
                .action(ArgAction::SetTrue)
                .help("Recursively process subdirectories in folder mode.")
                .required(false),
        )
}

/// Main function: parses CLI arguments, validates them, prompts for secret,
/// and dispatches to either single file processing or folder processing mode.
fn main() {
    // Parse command-line arguments.
    let matches = build_cli_command().get_matches(); // Call get_matches here

    let app_version_bytes = match parse_version_to_bytes(APP_VERSION_STR) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing application version: {}", e);
            std::process::exit(1);
        }
    };

    // Extract operation mode and format preferences.
    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");
    let output_format_preference = matches.get_one::<String>("format").unwrap().as_str();
    let base_image_path_str_opt = matches.get_one::<String>("base");
    let cli_password_opt = matches.get_one::<String>("password").cloned(); // Get password from CLI
    
    let ratio_from_cli = *matches.get_one::<u8>("ratio").unwrap(); 
    let user_explicitly_set_ratio = matches.value_source("ratio") == Some(clap::parser::ValueSource::CommandLine);
    let is_recursive = matches.get_flag("recursive");

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

    // Validate recursive flag usage
    if is_recursive && !input_path.is_dir() {
        eprintln!("Error: --recursive (-R) option can only be used when the input (-i) is a directory.");
        std::process::exit(1);
    }

    // Prompt for and validate the secret, or use CLI provided password.
    let encryption_secret: Zeroizing<String> = prompt_and_validate_secret(is_encrypt, cli_password_opt);

    // Dispatch to folder or single file processing.
    if input_path.is_dir() {
        // Input is a directory, process in folder mode.
        let output_path = Path::new(output_arg_str);
        if output_path.exists() && !output_path.is_dir() {
            eprintln!("Error: Input is a folder, so output '{}' must also be a folder or not exist (it will be created). It currently exists as a file.", output_arg_str);
            std::process::exit(1);
        }

        if is_encrypt {
            encrypt::process_folder_encryption( 
                input_arg_str, 
                output_arg_str, 
                &encryption_secret,
                output_format_preference, 
                base_image_path_str_opt, 
                lsb_bits_for_encryption,
                app_version_bytes,
                is_recursive, // Pass recursive flag
            );
        } else { // Decryption mode for folder
            decrypt::process_folder_decryption( 
                input_arg_str, 
                output_arg_str, 
                &encryption_secret,
                app_version_bytes,
                is_recursive, // Pass recursive flag
            );
        }
    } else {
        // Input is a single file.
        validate_file_exists(input_arg_str); // Ensure input file exists.
        if is_encrypt {
            match encrypt::encrypt_file(input_arg_str, output_arg_str, &encryption_secret, output_format_preference, base_image_path_str_opt.map(Path::new), lsb_bits_for_encryption, app_version_bytes) {
                Ok(_original_format) => { /* Success message printed by encrypt_file */ } 
                Err(e) => {
                    eprintln!("Error encrypting file: {}", e);
                    std::process::exit(1); // Exit on error for single file mode
                }
            }
        } else if is_decrypt {
            if let Err(e) = decrypt::decrypt_file(input_arg_str, output_arg_str, &encryption_secret, app_version_bytes) {
                eprintln!("Error decrypting file: {}", e);
                std::process::exit(1); // Exit on error for single file mode
            }
            // Success message is printed by decrypt_file
        }
    }
}