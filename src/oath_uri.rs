//! Read or write URIs start with `otpauth://totp/`.
use data_encoding::{DecodeError, BASE32_NOPAD};
use zeroize::Zeroize;

/// Read key bytes from a base32-encoded String.
pub fn key_from_base32(mut encoded: String) -> Result<Vec<u8>, DecodeError> {
    let mut tmp = encoded.to_ascii_uppercase();
    encoded.zeroize();
    let output = BASE32_NOPAD.decode(tmp.as_bytes());
    tmp.zeroize();
    output
}

/// Write key bytes to a base32-encoded String in uppercase.
pub fn key_to_base32_uppercase<T: AsRef<[u8]> + Zeroize>(mut key: T) -> String {
    let output = BASE32_NOPAD.encode(key.as_ref());
    key.zeroize();
    output
}

/// Write key bytes to a base32-encoded String in lowercase.
pub fn key_to_base32_lowercase<T: AsRef<[u8]> + Zeroize>(key: T) -> String {
    let mut uppercase = key_to_base32_uppercase(key);
    let output = uppercase.to_ascii_lowercase();
    uppercase.zeroize();
    output
}

