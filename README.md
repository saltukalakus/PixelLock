![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.png)

# 🔑 PixelLock 🔓

PixelLock is a command-line tool to secure your pictures with military-grade encryption. It helps enhance privacy and provide an additional layer of security while storing images. 

Image formats currently supported are JPEG, PNG, BMP, GIF, TIFF, and WebP. 

![Flow](https://github.com/saltukalakus/PixelLock/blob/main/Flow.png)


##  ✨ Building the Project ✨

Requirements
- Rust (1.87.0 or later)
- Cargo (1.87.0 or later)

[Go to the installation guide.](https://www.rust-lang.org/learn/get-started)

   ```bash
   git clone https://github.com/saltukalakus/PixelLock.git
   cd PixelLock
   cargo build --release
   ```

These steps generate the executable **PixelLock** in the `/target/release` directory.

## 🪄 Usage 🪄

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

Encrypting all images in a folder, embedding them into a provided base PNG:
```bash
./target/release/PixelLock -e -i ./image-folder -o ./stego_folder -b ./my_base.png
```

Decrypting all steganographic PNG images in a folder to an output folder:
```bash
./target/release/PixelLock -d -i ./stego_folder -o ./image-folder
```

For a full list of available options, try the help command 📖 :

```bash
./target/release/PixelLock --help  
```

## 💥💥💥 Security Challenge 💥💥💥

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret images in this [Gist](https://gist.github.com/saltukalakus/3ed86910ea2eee6c6e72f8def4c6017c). If you can decrypt at least one of the images, you win **500 GPB** 💰

## 👩‍⚖️ Disclaimer 👨‍⚖️

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
