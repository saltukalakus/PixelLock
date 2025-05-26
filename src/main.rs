use std::{fs, io::{self, Write}, path::{Path}};
use clap::{Arg, ArgAction, Command, ArgMatches};
use rpassword::read_password;
use zeroize::Zeroizing;

mod utils;

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

fn prompt_and_validate_secret(is_encryption_mode: bool) -> Zeroizing<String> {
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

fn build_cli_app() -> ArgMatches {
    Command::new("PixelLock")
        .version("1.0")
        .author("Saltuk Alakus")
        .about("Encrypts and decrypts images. \nIf -i is a folder, processes all supported files in that folder and -o must be an output folder.")
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
                .help("Path to the input file or folder"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Path to the output file or folder"),
        )
        .get_matches()
}

fn process_folder_mode(input_dir_str: &str, output_dir_str: &str, is_encrypt: bool, secret: &Zeroizing<String>) {
    let input_dir = Path::new(input_dir_str);
    let output_dir = Path::new(output_dir_str);

    if !output_dir.exists() {
        if let Err(e) = fs::create_dir_all(&output_dir) {
            eprintln!("Error: Could not create output directory '{}': {}", output_dir_str, e);
            std::process::exit(1);
        }
        println!("Created output directory: {:?}", output_dir);
    } else if !output_dir.is_dir() {
        eprintln!("Error: Output path '{}' exists but is not a directory.", output_dir_str);
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
                            
                            let should_process = if is_encrypt {
                                let supported_encryption_extensions = ["jpeg", "jpg", "bmp", "png", "gif", "tiff", "tif", "webp"];
                                supported_encryption_extensions.contains(&lower_extension.as_str())
                            } else { // Decrypting
                                lower_extension == "txt" // Encrypted files are expected to be .txt
                            };

                            if !should_process {
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
                                utils::encrypt_image(&current_input_file_path, &current_output_file_path, secret).map(|_| ())
                            } else {
                                utils::decrypt_image(&current_input_file_path, &current_output_file_path, secret)
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
            eprintln!("Error: Could not read input directory '{}': {}", input_dir_str, e);
            std::process::exit(1);
        }
    }
}

fn main() {
    let matches = build_cli_app();

    let is_decrypt = matches.get_flag("decrypt");
    let is_encrypt = matches.get_flag("encrypt");

    if is_decrypt == is_encrypt {
        eprintln!("Error: You must specify either --encrypt (-e) or --decrypt (-d).");
        std::process::exit(1);
    }

    let input_arg_str = matches.get_one::<String>("input").unwrap();
    let output_arg_str = matches.get_one::<String>("output").unwrap();
    
    let input_path = Path::new(input_arg_str);

    let encryption_secret: Zeroizing<String> = prompt_and_validate_secret(is_encrypt);

    if input_path.is_dir() {
        let output_path = Path::new(output_arg_str);
        if output_path.exists() && !output_path.is_dir() {
            eprintln!("Error: Input is a folder, so output '{}' must also be a folder or not exist (it will be created). It currently exists as a file.", output_arg_str);
            std::process::exit(1);
        }
        process_folder_mode(input_arg_str, output_arg_str, is_encrypt, &encryption_secret);
    } else {
        validate_file_exists(input_arg_str);
        if is_encrypt {
            match utils::encrypt_image(input_arg_str, output_arg_str, &encryption_secret) {
                Ok(_original_format) => {
                }
                Err(e) => {
                    eprintln!("Error encrypting file: {}", e);
                }
            }
        } else if is_decrypt {
            if let Err(e) = utils::decrypt_image(input_arg_str, output_arg_str, &encryption_secret) {
                eprintln!("Error decrypting file: {}", e);
            }
        }
    }
}