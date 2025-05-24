![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock is a command-line tool for encrypting and decrypting image files using AES-256 encryption in CBC mode. It allows you to securely encrypt image files and later decrypt them using a secret key.

The file format detection is supported for JPEG, PNG, and GIF. The file type is appended to the output file during decryption, so you don't necessarily need to pass it. See the example below.

### Build Requirements
- Rust (1.87.0 or later)
- Cargo (1.87.0 or later)

### Building the Project

   ```bash
   git clone https://github.com/saltukalakus/PixelLock.git
   cd PixelLock
   cargo build --release
   ```

### Usage

Encrypting an image.

```bash
PixelLock -e -i ./image.jpeg -o ./encrypted.enc
```

Decrypting an image.

```bash
PixelLock -d -i ./encrypted.enc -o ./new-image
```

### Security Challenge (NOT YET STARTED!)

There may be a security bug due to an incorrect implementation in this project and/or a vulnerable dependency used.

This is an open challenge for those interested in bug bounties. Find a way to decrypt the image in the [challenge directory](https://github.com/saltukalakus/PixelLock/blob/main/challange). If the image is correct, you win **500 GBP**!

Rules:

1. You should not target attacking my computer or any of my accounts I have online. Accessing the image that way somehow is not part of this bug bounty.

2. The only accepted method is through finding a vulnerability in this project or its dependencies and leveraging it to bypass the secret.

3. Open an issue and upload the decrypted image. Don't disclose how you were able to bypass the secret. I will reach out to you to understand how you bypassed the secret and make the payment.

4. Only **one** hacker who opens an issue first with the correct image wins.

5. The challange is 60 days time boxed. I will share the secret in the challange directory if no one can find a vulnerability. 

### Disclaimer

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
