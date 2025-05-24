![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.jpeg)

PixelLock is a command-line tool for encrypting and decrypting image files using AES-256 encryption in CBC mode. It allows you to securely encrypt image files and later decrypt them using a secret key.

The file format detection is supported for JPEG, PNG and GIF. File type is appended to the output file during decryption so you don't necessarilty need to pass it. See the example below.

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
