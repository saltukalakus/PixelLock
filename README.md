## PixelLock

PixelLock is a command-line tool for encrypting and decrypting image files using AES-256 encryption in CBC mode. It allows you to securely encrypt image files and later decrypt them using a secret key.

### Build Requirements
- Rust (1.87.0 or later)
- Cargo (1.87.0 or later)

### Build Steps
1. Clone the repository:
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

Decrypting an image. The format is appended by instropection so you may skip ht

```bash
PixelLock -d -i ./encrypted.enc -o ./new-image.jpeg
```