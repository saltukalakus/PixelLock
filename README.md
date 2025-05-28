![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock is a command-line tool to secure your pictures with a password. It helps enhance privacy and provide an additional layer of security.

AES-256-GCM is used for encrypting and decrypting images. Argon2 is used to hash the secret. 

Image formats currently supported for input are JPEG, PNG, BMP, GIF, TIFF, and WebP. The image type is extracted from the decrypted file (regardless of whether it was stored as `.txt` or embedded in a `.png`), and the file extension is automatically corrected upon decryption. This is handy as you may not know the file type of an encrypted file.

![Flow](https://github.com/saltukalakus/PixelLock/blob/main/Flow.png)

### Build Requirements
- Rust (1.87.0 or later)
- Cargo (1.87.0 or later)

[Go to the installation guide.](https://www.rust-lang.org/learn/get-started)

### Building the Project

   ```bash
   git clone https://github.com/saltukalakus/PixelLock.git
   cd PixelLock
   cargo build --release
   ```

These steps generate the executable **PixelLock** in the `/target/release` directory.

### Usage

You can choose the output format for encryption using the `-f` (or `--format`) option:
-   `-f png` (default): The tool embeds the encrypted binary data (salt + nonce + ciphertext) into the pixels of a PNG image using Least Significant Bit (LSB) steganography. The output file will have a `.png` extension.
    -   Optionally, you can provide a base PNG image using the `-b` (or `--base`) option (e.g., `-b base_image.png`). The encrypted data will be embedded into this image. If the base image is too small to hold the data, its content will be tiled onto a new, larger PNG image that is then used as the carrier.
    -   When using `-b` with `-f png`, you can also specify the LSB ratio with `-r <1-4>` (or `--ratio <1-4>`). This determines how many LSBs per color channel are used (default is 1). A higher ratio embeds more data per pixel but increases the visual impact on the base image. `-r` requires `-b`.
    -   If `-b` is not used with `-f png`, a new random PNG is generated, and 1 LSB per channel is used for embedding.
-   `-f txt`: The tool stores the encrypted file in a Base64-encoded text format with the `.txt` extension.

**Important Constraints for `-b` and `-r`:**
-   Both `-b` and `-r` can only be used during encryption (`-e`).
-   Both `-b` and `-r` require the format to be `png` (`-f png`).
-   The `-r` option specifically requires that `-b` is also provided.

When encrypting, if the input path (`-i`) is a folder, PixelLock will automatically process all supported image files within that folder (non-recursively). In this mode, the output path (`-o`) must specify a folder where the processed files will be saved. If the output folder does not exist, it will be created. The `-f`, `-b`, and `-r` options apply to all files processed in folder mode, following the constraints above.

During decryption, if the input path (`-i`) is a folder, PixelLock will process files with `.txt` or `.png` extensions only. For `.png` files, it assumes 1 LSB per channel was used for steganography.

Encrypting a single image (default to steganographic `.png` output, new random PNG, 1 LSB):
```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./stego_image_base_name
# Output will be ./stego_image_base_name.png
```

Encrypting a single image into a steganographic PNG using a base image (default 1 LSB):
```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./stego_image_base_name -b ./my_base.png
# Output will be ./stego_image_base_name.png (using my_base.png as a carrier, 1 LSB)
```

Encrypting a single image into a steganographic PNG using a base image and 2 LSBs per channel:
```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./stego_image_base_name -b ./my_base.png -r 2
# Output will be ./stego_image_base_name.png (using my_base.png, 2 LSBs)
```

Encrypting a single image into a Base64 text file:
```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./encrypted_base_name -f txt
# Output will be ./encrypted_base_name.txt
```

Encrypting all supported files in a folder (default to steganographic PNGs, new random PNGs for each, 1 LSB):
```bash
./target/release/PixelLock -e -i ./input-folder -o ./output-folder
```

Encrypting all supported files in a folder using a single base PNG and 2 LSBs for all:
```bash
./target/release/PixelLock -e -i ./input-folder -o ./output-folder -b ./my_base.png -r 2
```

Decrypting a single image (auto-detects if it's a `.txt` or `.png` encrypted file; for PNG, assumes 1 LSB):
```bash
./target/release/PixelLock -d -i ./encrypted_file.txt -o ./decrypted_image_base_name
# Or
./target/release/PixelLock -d -i ./stego_image.png -o ./decrypted_image_base_name
# Output extension will be based on detected original format, e.g., ./decrypted_image_base_name.jpeg
```

Decrypting all supported files in a folder:
```bash
./target/release/PixelLock -d -i ./input-folder-with-txt-and-png -o ./output-folder-for-decrypted
```

### Security Challenge (NOT YET STARTED!)

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret image in this [Gist](). If you can generate the original image, you win **500 GBP**!

**Rules:**

1. You should not target or attack my computer or any of my online accounts. Accessing the image that way is not eligible for the reward.

2. The accepted method for the reward is through finding a vulnerability in this project or its dependencies and leveraging it to bypass the secret. 

3. If you brute-force the secret and that works, you need to share proof of your brute-force attempt. I suggest not going that route, as it would probably be impractical. However, if you find a way to minimize the possible set of secrets to brute-force, that should be a valid approach.

4. Open an issue in this repository, upload the original image, and ping me @saltukalakus. Do not disclose how you were able to bypass the encryption. I will reach out to you to understand how you bypassed it.

5. Only the **first** hacker who opens an issue with the correct image wins.

6. The challenge is time-boxed. It will end on July 31, 2025, at 1 PM UTC. I will share the secret in the same Gist in the comments section if no one can decrypt it by then.

### Disclaimer 

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
