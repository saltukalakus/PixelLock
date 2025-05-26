![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock is a command-line tool to secure your pictures with a password. It helps to enhance privacy and provide an additional layer of security.

AES-256-GCM is used for encrypting and decrypting images. Argon2 is used to hash the secret. The tool stores the encrypted file in a Base64-encoded text format with the `.txt` extension.

Image formats currently supported are JPEG, PNG, BMP, GIF, TIFF, and WebP. The image type is extracted from the encrypted file after decryption, and the file extension type is automatically corrected. This is handy as you may not know the file type of an encrypted file.

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

These steps generate the executable **PixelLock** in the `/target/release` folder.

### Usage

Encrypting an image.

```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./encrypted.txt
```
Encrypting all supported files in a folder.

```bash
./target/release/PixelLock -e -f -i ./input-folder -o ./output-folder
```

Decrypting an image.

```bash
./target/release/PixelLock -d -i ./encrypted.txt -o ./image2.jpeg
```
Decrypting all supported files in a folder.

```bash
./target/release/PixelLock -d -f -i ./input-folder -o ./output-folder
```

### Security Challenge (NOT YET STARTED!)

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret image in this [Gist](). If you can generate the original image, you win **500 GBP**!

**Rules:**

1. You should not target attacking my computer or any of my online accounts. Somehow, accessing the image that way is not eligible for the reward.

2. The accepted method for the reward is through finding a vulnerability in this project or its dependencies and leveraging it to bypass the secret. 

3. If you brute-forced the secret and that worked, you need to share proof of your brute-force attempt. I suggest not going that route as it would probably be impractical. But if you found a way to minimize the possible set of secrets to brute-force, that should be a valid approach.

4. Open an issue in this repository and upload the original image and ping me @saltukalakus. Don't disclose how you were able to bypass the encryption. I will reach out to you to understand how you bypassed it.

5. Only the **first** hacker who opens an issue with the correct image wins.

6. The challenge is time-boxed. It will end on the 31st of July 2025, 1 PM UTC. I will share the secret in the same Gist in the comments section if no one can decrypt it until then.

### Disclaimer 

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
