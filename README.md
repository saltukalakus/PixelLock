![PixelLock](https://github.com/saltukalakus/PixelLock/blob/main/PixelLock.png)

[![Rust CI](https://github.com/saltukalakus/PixelLock/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/saltukalakus/PixelLock/actions/workflows/rust.yml)

##

PixelLock is a command-line tool to secure your files with military-grade encryption. It helps enhance privacy and provide an additional layer of security while storing your sensitive files. 

Any file can be secured with PixelLock. Most file types are supported by file format detection. PixelLock falls back to using file extension as a source of truth if the format is not recognized.

The tool allows generating encrypted files in two different formats: Base64 text or a PNG image. 

You may optionally pass a PNG-formatted carrier base image to hide your encrypted file in it. When the base image is provided, the tool allows configuring the blending ratio to adjust the output image distortion level vs the final image size. If the base image size isn't sufficient to hide your secret file, PixelLock automatically tiles it to enlarge the base image.

Feel free to open any feature requests in the issues section. Please check existing open issues before opening a new one. Also don't forget to ⭐️ the project if you find it useful 🤩

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

These steps generate the executable **PixelLock** in the `/target/release` directory. I have used a Mac M2 Pro for testing. If you experience any issues on other hardware or operating systems, please open an issue.

## 🪄 Usage 🪄

* Encrypting a single file, embedding it into a provided base PNG:
```bash
> PixelLock -e -i ./secret_image.jpeg -o ./stego_image -b ./my_base.png
# Output will be ./stego_image.png (using my_base.png as a carrier, 1 LSB)
```

* Decrypting a steganographic PNG image to reveal the secret file:
```bash
> PixelLock -d -i ./stego_image.png -o ./secret_image
# Output extension will be based on detected original format, e.g., ./secret_image.jpeg
```

* Encrypting all files in a folder, embedding them into a provided base PNG:
```bash
> PixelLock -e -i ./image-folder -o ./stego_folder -b ./my_base.png

Input
 ├── img-folder
     └── Image1.jpg
     └── Image2.png
     └── doc.pdf
Output
 ├── stego_folder
     └── Image1.jpg.png
     └── Image2.png.png
     └── doc.pdf.png
```

* Decrypting all steganographic PNG images in a folder to an output folder:
```bash
> PixelLock -d -i ./stego_folder -o ./image-folder

Input
 ├── stego_folder
     └── Image1.jpg.png
     └── Image2.png.png
     └── doc.pdf.png
Output
 ├── img-folder
     └── Image1.jpg
     └── Image2.png
     └── doc.pdf
```

*  📖 For a full list of available options, try the help command:

```bash
> PixelLock --help  
```

## 🧪 Running Tests 🧪

To run end-to-end tests execute the `cargo test` command in the project root directory. 

```bash
> cargo test  
```
The tests in the `./tests` folder create unique temporary subdirectories under `./tests/tmp/` for their output. Each specific test operation (e.g., for a particular image and settings) will ensure its output subdirectory is cleared before it runs, providing a clean environment for that operation's artifacts. The `./tests/tmp/` directory itself will contain these subdirectories, which are not deleted after the entire test suite finishes, allowing for inspection of outputs.


## 💥 Security Challenge 💥

This is an open challenge for those interested in bug bounties. Find a way to decrypt the secret images in this [Gist](https://gist.github.com/saltukalakus/dc02e23eb2cf51c414bc58c8002af32e). If you can decrypt at least one of the images, you win 500 GBP 💰 

The challenge is time-boxed. It will end on July 31, 2025, at 1 PM UTC. I will share the secret in the same Gist in the comments section if no one can hack it by then. All the other details are in the Gist including the terms and conditions.

To the best of my knowledge, the security choices and the libraries used in this project are solid. If you are able to break it, you must be a real 🧙‍♂️.

## 👩‍⚖️ Disclaimer 👨‍⚖️

PixelLock is provided "as is" without any warranties or guarantees of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. The author of this tool disclaims all liability for any damages, losses, or claims arising from the use or misuse of this tool. By using PixelLock, you acknowledge and agree that it is your sole responsibility to ensure the security and proper usage of this tool, and the author shall not be held liable for any consequences resulting from its use.
