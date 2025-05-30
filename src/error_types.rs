use std::{array::TryFromSliceError, fmt, io::Error as IoError, str::Utf8Error};
use aes_gcm::aead::Error as AeadError;
use argon2::{Error as Argon2Error, password_hash::Error as PasswordHashError};
use base64::DecodeError as Base64DecodeError;
use image::ImageError as ImgError;

// Custom Error Type
#[derive(Debug)]
pub enum CryptoImageError {
    Io(IoError),
    Image(ImgError),
    Encryption(String),
    Decryption(String),
    Aead(AeadError),
    Argon2(Argon2Error),
    PasswordHash(PasswordHashError),
    Base64(Base64DecodeError),
    Steganography(String),
    PasswordComplexity(String),
    InvalidParameter(String),
    Utf8Error(Utf8Error),
    TryFromSlice(TryFromSliceError),
}

impl fmt::Display for CryptoImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoImageError::Io(e) => write!(f, "IO error: {}", e),
            CryptoImageError::Image(e) => write!(f, "Image processing error: {}", e),
            CryptoImageError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            CryptoImageError::Decryption(msg) => write!(f, "Decryption error: {}", msg),
            CryptoImageError::Aead(_) => write!(f, "AEAD operation error"),
            CryptoImageError::Argon2(e) => write!(f, "Argon2 error: {}", e),
            CryptoImageError::PasswordHash(e) => write!(f, "Password hashing error: {}", e),
            CryptoImageError::Base64(e) => write!(f, "Base64 decoding error: {}", e),
            CryptoImageError::Steganography(msg) => write!(f, "Steganography error: {}", msg),
            CryptoImageError::PasswordComplexity(msg) => write!(f, "Password complexity error: {}", msg),
            CryptoImageError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            CryptoImageError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            CryptoImageError::TryFromSlice(e) => write!(f, "Slice to array conversion error: {}", e),
        }
    }
}

impl std::error::Error for CryptoImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoImageError::Io(e) => Some(e),
            CryptoImageError::Image(e) => Some(e),
            CryptoImageError::Aead(_) => None, 
            CryptoImageError::Argon2(_) => None, 
            CryptoImageError::PasswordHash(_) => None, 
            CryptoImageError::Base64(e) => Some(e),
            CryptoImageError::Utf8Error(e) => Some(e),
            CryptoImageError::TryFromSlice(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IoError> for CryptoImageError {
    fn from(err: IoError) -> Self {
        CryptoImageError::Io(err)
    }
}

impl From<ImgError> for CryptoImageError {
    fn from(err: ImgError) -> Self {
        CryptoImageError::Image(err)
    }
}

impl From<AeadError> for CryptoImageError {
    fn from(err: AeadError) -> Self {
        CryptoImageError::Aead(err)
    }
}

impl From<Argon2Error> for CryptoImageError {
    fn from(err: Argon2Error) -> Self {
        CryptoImageError::Argon2(err)
    }
}

impl From<PasswordHashError> for CryptoImageError {
    fn from(err: PasswordHashError) -> Self {
        CryptoImageError::PasswordHash(err)
    }
}

impl From<Base64DecodeError> for CryptoImageError {
    fn from(err: Base64DecodeError) -> Self {
        CryptoImageError::Base64(err)
    }
}

impl From<Utf8Error> for CryptoImageError {
    fn from(err: Utf8Error) -> Self {
        CryptoImageError::Utf8Error(err)
    }
}

impl From<TryFromSliceError> for CryptoImageError {
    fn from(err: TryFromSliceError) -> Self {
        CryptoImageError::TryFromSlice(err)
    }
}
