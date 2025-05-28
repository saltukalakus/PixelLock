![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock is a command-line tool to secure your pictures with military-grade encryption. It helps enhance privacy and provide an additional layer of security while storing images.

Image formats currently supported are JPEG, PNG, BMP, GIF, TIFF, and WebP. 

In the default operation mode, the secret image is blended into a carrier PNG image. 

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

Encrypting a single image, embedding it into a provided base PNG:
```bash
./target/release/PixelLock -e -i ./secret_image.jpeg -o ./stego_image -b ./my_base.png
# Output will be ./stego_image.png (using my_base.png as a carrier, 1 LSB)
```

Decrypting a steganographic PNG image to reveal the secret image:
```bash
./target/release/PixelLock -d -i ./stego_image.png -o ./secret_image
# Output extension will be based on detected original format, e.g., ./secret_image.jpeg
```
For a full list of available options, try the help command:

```bash
./target/release/PixelLock --help  
```

### Security Challenge

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret images in this [Gist](https://gist.github.com/saltukalakus/3ed86910ea2eee6c6e72f8def4c6017c). If you can generate one of the original images, you win **500 GBP**! 

All of the images are hiding different secret images. The base image and password used are the same in all samples. The samples are encrypted with the default usage shown in the Usage section of this README file.

**Rules:**

1. You should not target or attack my computer or any of my online accounts. Accessing the image that way is not eligible for the reward.

2. The accepted method for the reward is through finding a vulnerability in this project or its dependencies and leveraging it to bypass the security. 

3. If you brute-force the secret and that works, you need to share proof of your brute-force attempt. I suggest not going that route, as it would probably be impractical. However, if you find a way to minimize the possible set of secrets to brute-force, that may be a valid approach.

4. Open an issue in this repository, upload one of the original images, and ping me @saltukalakus. Please do not disclose how you were able to bypass the encryption. I will reach out to you to understand how you bypassed it.

5. Only the **first** hacker who opens an issue with the correct image wins.

6. The challenge is time-boxed. It will end on July 31, 2025, at 1 PM UTC. I will share the secret in the same Gist in the comments section if no one has found it by then.

### Disclaimer 

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
