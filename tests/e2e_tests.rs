use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PIXELLOCK_EXE: &str = env!("CARGO_BIN_EXE_pixellock");
const TEST_FILES_DIR: &str = "./tests/files";
const BASE_IMAGE_NAME: &str = "base_image.png";
const TEST_PASSWORD: &str = "TestPassword123!@#$"; // Meets complexity requirements

const PERSISTENT_TMP_DIR_BASE: &str = "./tests/tmp";

struct TestFiles {
    name: &'static str,
    extension: &'static str,
}

const TEST_FILES: &[TestFiles] = &[
    TestFiles { name: "test_image", extension: "jpeg" },
    TestFiles { name: "test_image", extension: "png" },
    TestFiles { name: "test_image", extension: "bmp" },
    TestFiles { name: "test_image", extension: "gif" },
    TestFiles { name: "test_image", extension: "tiff" },
    TestFiles { name: "test_image", extension: "webp" },
    TestFiles { name: "test_html", extension: "html" },
    TestFiles { name: "test_csv", extension: "csv" },
    TestFiles { name: "test_ods", extension: "ods" },
    TestFiles { name: "test_pdf", extension: "pdf" },
    TestFiles { name: "test_xlsx", extension: "xlsx" },
    TestFiles { name: "test_zip", extension: "zip" },
];

fn run_pixel_lock(args: &[String]) -> Result<Output, std::io::Error> {
    Command::new(PIXELLOCK_EXE).args(args).output()
}

fn compare_files(path1: &Path, path2: &Path) -> bool {
    if !path1.exists() || !path2.exists() {
        eprintln!("One or both files do not exist for comparison: {:?} vs {:?}", path1, path2);
        return false;
    }
    let mut file1 = match fs::File::open(path1) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file {:?}: {}", path1, e);
            return false;
        }
    };
    let mut file2 = match fs::File::open(path2) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file {:?}: {}", path2, e);
            return false;
        }
    };

    let mut buffer1 = Vec::new();
    let mut buffer2 = Vec::new();

    if file1.read_to_end(&mut buffer1).is_err() || file2.read_to_end(&mut buffer2).is_err() {
        eprintln!("Failed to read one or both files for comparison.");
        return false;
    }
    
    buffer1 == buffer2
}

fn setup_test_environment(path_parts: &[&str]) -> PathBuf {
    let base_tmp_dir = PathBuf::from(PERSISTENT_TMP_DIR_BASE);
    // Parent ./tests/tmp/ directory will be created if it doesn't exist by create_dir_all below.

    let mut specific_test_tmp_dir = base_tmp_dir;
    for part in path_parts {
        specific_test_tmp_dir.push(part);
    }

    // If the specific directory for this test iteration already exists, remove it to ensure a clean state.
    if specific_test_tmp_dir.exists() {
        fs::remove_dir_all(&specific_test_tmp_dir)
            .expect(&format!("Failed to remove existing specific temp directory: {:?}", specific_test_tmp_dir));
    }

    // Now create it fresh. This will also create ./tests/tmp/ if it doesn't exist.
    fs::create_dir_all(&specific_test_tmp_dir)
        .expect(&format!("Failed to create specific persistent temp directory: {:?}", specific_test_tmp_dir));
    
    specific_test_tmp_dir
}

fn get_test_file_path(file_spec: &TestFiles) -> PathBuf {
    PathBuf::from(TEST_FILES_DIR).join(format!("{}.{}", file_spec.name, file_spec.extension))
}

fn get_base_image_path() -> PathBuf {
    PathBuf::from(TEST_FILES_DIR).join(BASE_IMAGE_NAME)
}

// --- Single File Tests ---
#[test]
fn test_single_file_txt_format() {
    for file_spec in TEST_FILES {
        let original_file_path = get_test_file_path(file_spec);
        if !original_file_path.exists() {
            eprintln!("Skipping test for {:?}: Original file not found.", original_file_path);
            continue;
        }

        let temp_dir_path = setup_test_environment(&["test_single_file_txt_format", file_spec.extension]);
        let encrypted_output_base = temp_dir_path.join("encrypted_single_txt");
        let decrypted_output_base = temp_dir_path.join("decrypted_single_txt"); // Base name for decrypted output

        // Encrypt
        let encrypt_args = vec![
            "-e".to_string(),
            "-i".to_string(), original_file_path.to_str().unwrap().to_string(),
            "-o".to_string(), encrypted_output_base.to_str().unwrap().to_string(),
            "-f".to_string(), "txt".to_string(),
            "-p".to_string(), TEST_PASSWORD.to_string(),
        ];
        let output_enc = run_pixel_lock(&encrypt_args).expect("Encryption failed");
        assert!(output_enc.status.success(), "Encryption failed for {:?}: STDOUT: {}, STDERR: {}", original_file_path, String::from_utf8_lossy(&output_enc.stdout), String::from_utf8_lossy(&output_enc.stderr));
        
        let encrypted_file_path = encrypted_output_base.with_extension("txt");
        assert!(encrypted_file_path.exists(), "Encrypted file {:?} not found", encrypted_file_path);

        // Decrypt
        let decrypt_args = vec![
            "-d".to_string(),
            "-i".to_string(), encrypted_file_path.to_str().unwrap().to_string(),
            "-o".to_string(), decrypted_output_base.to_str().unwrap().to_string(),
            "-p".to_string(), TEST_PASSWORD.to_string(),
        ];
        let output_dec = run_pixel_lock(&decrypt_args).expect("Decryption process failed to start");
        
        // --- BEGIN ADDED DEBUGGING ---
        println!("\n--- Debugging test_single_file_txt_format for original: {:?} ---", original_file_path);
        println!("Encrypted file path: {:?}", encrypted_file_path);
        println!("Decrypted output base path (argument to -o): {:?}", decrypted_output_base);
        println!("Decrypt STDOUT:\n{}", String::from_utf8_lossy(&output_dec.stdout));
        println!("Decrypt STDERR:\n{}", String::from_utf8_lossy(&output_dec.stderr));
        println!("Decrypt Status: {:?}", output_dec.status);

        println!("Contents of temp_dir_path ({:?}):", temp_dir_path);
        match fs::read_dir(&temp_dir_path) {
            Ok(entries) => {
                let mut found_any = false;
                for entry in entries {
                    if let Ok(entry) = entry {
                        println!("  - {:?}", entry.path());
                        found_any = true;
                    }
                }
                if !found_any {
                    println!("  (Directory is empty or unreadable entries)");
                }
            }
            Err(e) => println!("  Error reading dir {:?}: {}", temp_dir_path, e),
        }
        // --- END ADDED DEBUGGING ---

        assert!(output_dec.status.success(), "Decryption process failed for {:?}: STDOUT: {}, STDERR: {}", encrypted_file_path, String::from_utf8_lossy(&output_dec.stdout), String::from_utf8_lossy(&output_dec.stderr));

        // Determine actual decrypted file path
        let expected_decrypted_path_with_ext = decrypted_output_base.with_extension(file_spec.extension);
        let actual_decrypted_path = if expected_decrypted_path_with_ext.exists() {
            expected_decrypted_path_with_ext
        } else if decrypted_output_base.exists() { // Check base path if extension wasn't added
            decrypted_output_base.clone()
        } else {
            panic!("Neither expected decrypted file {:?} nor base path {:?} found after TXT decryption.", expected_decrypted_path_with_ext, decrypted_output_base);
        };
        assert!(compare_files(&original_file_path, &actual_decrypted_path), "Files differ after TXT encrypt/decrypt for {:?}", original_file_path);
    }
}

#[test]
fn test_single_file_png_no_base() {
    for file_spec in TEST_FILES {
        let original_file_path = get_test_file_path(file_spec);
         if !original_file_path.exists() {
            eprintln!("Skipping test for {:?}: Original file not found.", original_file_path);
            continue;
        }
        let temp_dir_path = setup_test_environment(&["test_single_file_png_no_base", file_spec.extension]);
        let encrypted_output_base = temp_dir_path.join("encrypted_single_png_no_base");
        let decrypted_output_base = temp_dir_path.join("decrypted_single_png_no_base");

        // Encrypt
        let encrypt_args = vec![
            "-e".to_string(),
            "-i".to_string(), original_file_path.to_str().unwrap().to_string(),
            "-o".to_string(), encrypted_output_base.to_str().unwrap().to_string(),
            "-f".to_string(), "png".to_string(),
            "-p".to_string(), TEST_PASSWORD.to_string(),
        ];
        let output_enc = run_pixel_lock(&encrypt_args).expect("Encryption failed");
        assert!(output_enc.status.success(), "Encryption failed for {:?} (PNG no base): STDOUT: {}, STDERR: {}", original_file_path, String::from_utf8_lossy(&output_enc.stdout), String::from_utf8_lossy(&output_enc.stderr));
        
        let encrypted_file_path = encrypted_output_base.with_extension("png");
        assert!(encrypted_file_path.exists());

        // Decrypt
        let decrypt_args = vec![
            "-d".to_string(),
            "-i".to_string(), encrypted_file_path.to_str().unwrap().to_string(),
            "-o".to_string(), decrypted_output_base.to_str().unwrap().to_string(),
            "-p".to_string(), TEST_PASSWORD.to_string(),
        ];
        let output_dec = run_pixel_lock(&decrypt_args).expect("Decryption failed");
        assert!(output_dec.status.success(), "Decryption failed for {:?} (PNG no base): STDOUT: {}, STDERR: {}", encrypted_file_path, String::from_utf8_lossy(&output_dec.stdout), String::from_utf8_lossy(&output_dec.stderr));

        // Determine actual decrypted file path
        let expected_decrypted_path_with_ext = decrypted_output_base.with_extension(file_spec.extension);
        let actual_decrypted_path = if expected_decrypted_path_with_ext.exists() {
            expected_decrypted_path_with_ext
        } else if decrypted_output_base.exists() {
            decrypted_output_base.clone()
        } else {
            panic!("Neither expected decrypted file {:?} nor base path {:?} found after PNG (no base) decryption.", expected_decrypted_path_with_ext, decrypted_output_base);
        };
        assert!(compare_files(&original_file_path, &actual_decrypted_path), "Files differ after PNG (no base) encrypt/decrypt for {:?}", original_file_path);
    }
}

#[test]
fn test_single_file_png_with_base_ratios() {
    let base_image_path = get_base_image_path();
    if !base_image_path.exists() {
        panic!("Base image {:?} not found. Cannot run steganography tests. Ensure your test_image.* files are small to prevent timeouts.", base_image_path);
    }

    for file_spec in TEST_FILES {
        let original_file_path = get_test_file_path(file_spec);
        if !original_file_path.exists() {
            eprintln!("Skipping test for {:?} (ratio loop): Original file not found.", original_file_path);
            continue;
        }

        for ratio in 1..=4 {
            let ratio_str = format!("ratio{}", ratio);
            let temp_dir_path = setup_test_environment(&[
                "test_single_file_png_with_base_ratios", 
                file_spec.extension, 
                &ratio_str
            ]);
            let encrypted_output_base = temp_dir_path.join(format!("encrypted_single_png_base_r{}", ratio));
            let decrypted_output_base = temp_dir_path.join(format!("decrypted_single_png_base_r{}", ratio));

            // Encrypt
            let encrypt_args = vec![
                "-e".to_string(),
                "-i".to_string(), original_file_path.to_str().unwrap().to_string(),
                "-o".to_string(), encrypted_output_base.to_str().unwrap().to_string(),
                "-f".to_string(), "png".to_string(),
                "-b".to_string(), base_image_path.to_str().unwrap().to_string(),
                "-r".to_string(), ratio.to_string(),
                "-p".to_string(), TEST_PASSWORD.to_string(),
            ];
            let output_enc = run_pixel_lock(&encrypt_args).expect("Encryption failed");
            assert!(output_enc.status.success(), "Encryption failed for {:?} (PNG base, ratio {}): STDOUT: {}, STDERR: {}", original_file_path, ratio, String::from_utf8_lossy(&output_enc.stdout), String::from_utf8_lossy(&output_enc.stderr));
            
            let encrypted_file_path = encrypted_output_base.with_extension("png");
            assert!(encrypted_file_path.exists());

            // Decrypt
            let decrypt_args = vec![
                "-d".to_string(),
                "-i".to_string(), encrypted_file_path.to_str().unwrap().to_string(),
                "-o".to_string(), decrypted_output_base.to_str().unwrap().to_string(),
                "-p".to_string(), TEST_PASSWORD.to_string(),
            ];
            let output_dec = run_pixel_lock(&decrypt_args).expect("Decryption failed");
            assert!(output_dec.status.success(), "Decryption failed for {:?} (PNG base, ratio {}): STDOUT: {}, STDERR: {}", encrypted_file_path, ratio, String::from_utf8_lossy(&output_dec.stdout), String::from_utf8_lossy(&output_dec.stderr));

            // Determine actual decrypted file path
            let expected_decrypted_path_with_ext = decrypted_output_base.with_extension(file_spec.extension);
            let actual_decrypted_path = if expected_decrypted_path_with_ext.exists() {
                expected_decrypted_path_with_ext
            } else if decrypted_output_base.exists() {
                decrypted_output_base.clone()
            } else {
                panic!("Neither expected decrypted file {:?} nor base path {:?} found after PNG (base, ratio {}) decryption.", expected_decrypted_path_with_ext, decrypted_output_base, ratio);
            };
            assert!(compare_files(&original_file_path, &actual_decrypted_path), "Files differ after PNG (base, ratio {}) encrypt/decrypt for {:?}", ratio, original_file_path);
        }
    }
}

// --- Folder Mode Tests ---
fn test_folder_mode_generic(
    test_output_dir: &Path, // Renamed from temp_dir to avoid confusion, this is the specific test's output dir
    format_str: &str,
    base_image_opt: Option<&PathBuf>,
    ratio_opt: Option<u8>
) {
    let input_folder_path = PathBuf::from(TEST_FILES_DIR);
    // test_output_dir is already the unique base for this test run (e.g., ./tests/tmp/test_folder_mode_txt_format/)
    let encrypted_output_folder = test_output_dir.join("encrypted_folder_output");
    fs::create_dir_all(&encrypted_output_folder).unwrap();
    let decrypted_output_folder = test_output_dir.join("decrypted_folder_output");
    fs::create_dir_all(&decrypted_output_folder).unwrap();

    // Encrypt
    let mut encrypt_args = vec![
        "-e".to_string(),
        "-i".to_string(), input_folder_path.to_str().unwrap().to_string(),
        "-o".to_string(), encrypted_output_folder.to_str().unwrap().to_string(),
        "-f".to_string(), format_str.to_string(),
        "-p".to_string(), TEST_PASSWORD.to_string(),
    ];
    if let Some(base_path) = base_image_opt {
        encrypt_args.push("-b".to_string());
        encrypt_args.push(base_path.to_str().unwrap().to_string());
        if let Some(ratio) = ratio_opt {
            encrypt_args.push("-r".to_string());
            encrypt_args.push(ratio.to_string());
        }
    }

    let output_enc = run_pixel_lock(&encrypt_args).expect("Folder encryption failed");
    assert!(output_enc.status.success(), "Folder encryption failed (format: {}, base: {:?}, ratio: {:?}): STDOUT: {}, STDERR: {}", format_str, base_image_opt.is_some(), ratio_opt, String::from_utf8_lossy(&output_enc.stdout), String::from_utf8_lossy(&output_enc.stderr));

    // Decrypt
    let decrypt_args = vec![
        "-d".to_string(),
        "-i".to_string(), encrypted_output_folder.to_str().unwrap().to_string(),
        "-o".to_string(), decrypted_output_folder.to_str().unwrap().to_string(),
        "-p".to_string(), TEST_PASSWORD.to_string(),
    ];
    let output_dec = run_pixel_lock(&decrypt_args).expect("Folder decryption process failed to start");
    
    // --- BEGIN ADDED DEBUGGING for FOLDER MODE ---
    println!("\n--- Debugging test_folder_mode_generic (format: {}, base: {:?}, ratio: {:?}) ---", format_str, base_image_opt.is_some(), ratio_opt);
    println!("Encrypted input folder for decryption: {:?}", encrypted_output_folder);
    println!("Decrypted output folder (argument to -o): {:?}", decrypted_output_folder);
    println!("Decrypt STDOUT:\n{}", String::from_utf8_lossy(&output_dec.stdout));
    println!("Decrypt STDERR:\n{}", String::from_utf8_lossy(&output_dec.stderr));
    println!("Decrypt Status: {:?}", output_dec.status);

    println!("Contents of decrypted_output_folder ({:?}):", decrypted_output_folder);
    match fs::read_dir(&decrypted_output_folder) {
        Ok(entries) => {
            let mut found_any = false;
            for entry in entries {
                if let Ok(entry) = entry {
                    println!("  - {:?}", entry.path());
                    found_any = true;
                }
            }
            if !found_any {
                println!("  (Decrypted output directory is empty or unreadable entries)");
            }
        }
        Err(e) => println!("  Error reading decrypted_output_folder {:?}: {}", decrypted_output_folder, e),
    }
    // --- END ADDED DEBUGGING for FOLDER MODE ---

    assert!(output_dec.status.success(), "Folder decryption process failed (format: {}, base: {:?}, ratio: {:?}): STDOUT: {}, STDERR: {}", format_str, base_image_opt.is_some(), ratio_opt, String::from_utf8_lossy(&output_dec.stdout), String::from_utf8_lossy(&output_dec.stderr));

    // Verify decrypted files
    for file_spec in TEST_FILES {
        let original_file_path = get_test_file_path(file_spec);
        if !original_file_path.exists() { // Skip if original doesn't exist
             eprintln!("Skipping verification for {:?}: Original file not found.", original_file_path);
            continue;
        }
        
        let original_file_basename = format!("{}.{}", file_spec.name, file_spec.extension);
        
        // PixelLock's folder decryption saves files with their original names + detected extensions.
        // Example: If original was "test_image.jpeg", and it was encrypted (e.g. to "test_image.jpeg.txt" 
        // if my previous assumption about encryption naming was wrong, or "test_image.jpeg.encrypted.txt" if it was right),
        // the decryption process will output "test_image.jpeg" into the decrypted_output_folder.
        let actual_decrypted_path = decrypted_output_folder.join(&original_file_basename);

        if !actual_decrypted_path.exists() {
            // Fallback: if the file exists without an extension (e.g. if detect_file_format failed for some reason)
            // This case might not be hit if detect_file_format is robust or if PixelLock always adds some extension.
            // The current PixelLock STDOUT shows it always saves with a detected extension.
            // However, the original single-file test logic had a fallback for no extension, so keeping a similar thought.
            // For folder mode, PixelLock's STDOUT shows it saves as `stem.detected_extension`.
            // The `stem` used by `process_folder_decryption` appears to be the original filename without its final encrypted extension.
            // e.g., for "test_image.jpeg.txt", stem is "test_image.jpeg".
            // So, `actual_decrypted_path` as defined above should be correct.
            panic!("Expected decrypted file {:?} not found in folder mode for original {:?}. Check PixelLock's output naming in folder decryption.", 
                   actual_decrypted_path, original_file_basename);
        };
        
        assert!(compare_files(&original_file_path, &actual_decrypted_path), "Files differ after folder encrypt/decrypt for {:?} (format: {}, base: {:?}, ratio: {:?})", original_file_path, format_str, base_image_opt.is_some(), ratio_opt);
    }
}

#[test]
fn test_folder_mode_txt_format() {
    let test_dir = setup_test_environment(&["test_folder_mode_txt_format"]);
    test_folder_mode_generic(&test_dir,"txt", None, None);
}

#[test]
fn test_folder_mode_png_no_base() {
    let test_dir = setup_test_environment(&["test_folder_mode_png_no_base"]);
    test_folder_mode_generic(&test_dir, "png", None, None);
}

#[test]
fn test_folder_mode_png_with_base_ratio1() {
    let base_image_path = get_base_image_path();
    if !base_image_path.exists() {
        panic!("Base image {:?} not found. Cannot run folder steganography test.", base_image_path);
    }
    let test_dir = setup_test_environment(&["test_folder_mode_png_with_base_ratio1"]);
    test_folder_mode_generic(&test_dir, "png", Some(&base_image_path), Some(1));
}
