![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock allows you to securely store your pictures and then later retrieve them using a secret key only you know.

It is a command-line tool for encrypting and decrypting image files using AES-256 encryption in CBC mode. It stores the encrypted file in a readable BASE64-encoded format.

The file type detection is supported for JPEG, PNG, and GIF. The type is extracted from the encrypted file after decryption. That is handy as you may not know the file type of an encrypted file.

Technically, PixelLock can be used to encrypt any file type, but then you need to make sure the file extension for the encrypted file is the same as the original file so that you can know the type after decrypting. 

Future versions of the tool may add new features that make it useful only for images.

### Build Requirements
- Rust (1.87.0 or later)
- Cargo (1.87.0 or later)

[Go to the installation guide.](https://www.rust-lang.org/learn/get-started)

### Building the Project

   ```bash
   git clone https://github.com/saltukalakus/PixelLock.git
   cd PixelLock
   cargo build --releasehub.com/saltukalakus/PixelLock.git
   ```

These steps generate the executable **PixelLock** in the `/target/release` folder.

### Usage

Encrypting an image.

```bash
./target/release/PixelLock -e -i ./image.jpeg -o ./encrypted.txt
```
Decrypting an image.

```bash
./target/release/PixelLock -d -i ./encrypted.txt -o ./image2.jpeg
```


### Security Challenge (NOT YET STARTED!)

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret image in this [Gist](). If you can generate the original image, you win **500 GBP**!

**Rules:**

1. You should not target attacking my computer or any of my online accounts. Somehow, accessing the image that way is not eligible for the reward.

2. The accepted method for the reward is through finding a vulnerability in this project or its dependencies and leveraging it to bypass the secret. 

3. If you brute-forced the secret and that worked, you need to share proof of your brute-force attempt. I suggest not going that route as it would probably be impractical. But if you found a way to minimize the possible set of secrets, that should be a valid approach.

4. Open an issue in this repository and upload the secret image and ping me @saltukalakus. Don't disclose how you were able to bypass the encryption. I will reach out to you to understand how you bypassed the secret and make the payment.

5. Only the **first** hacker who opens an issue with the correct image wins.

6. The challenge is time-boxed. It will end on the 31st of July 2025. I will share the secret in the same Gist in the comments section if no one can decrypt it until then.

### Disclaimer 

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
