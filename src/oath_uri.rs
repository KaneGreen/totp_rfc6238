//! Read or write URIs start with `otpauth://totp/`.
use data_encoding::{DecodeError, BASE32_NOPAD};
use zeroize::Zeroize;

/// Read key bytes from a base32-encoded String.
///
/// # Example
/// ```
/// use totp_rfc6238::oath_uri::key_from_base32;
/// let expected = b"1234567890 AbC\ndeF";
/// // Base32 only uses uppercase letters. So, lowercase letters will
/// // automatically be converted to uppercase letters.
/// let input = String::from("GEZDGNBVGY3TQOJQEBAWEQYKMRSUM");
/// let output = key_from_base32(input).unwrap();
/// assert_eq!(&output[..], expected);
/// ```
pub fn key_from_base32(mut encoded: String) -> Result<Vec<u8>, DecodeError> {
    let mut tmp = encoded.to_ascii_uppercase();
    encoded.zeroize();
    let output = BASE32_NOPAD.decode(tmp.as_bytes());
    tmp.zeroize();
    output
}

/// Write key bytes to a base32-encoded String in uppercase.
///
/// # Example
/// ```
/// use totp_rfc6238::oath_uri::key_to_base32_uppercase;
/// let expected = "GEZDGNBVGY3TQOJQEBAWEQYKMRSUM";
///
/// let input = [
///     b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b' ', b'A', b'b', b'C', b'\n',
///     b'd', b'e', b'F',
/// ];
/// let output = key_to_base32_uppercase(input);
/// assert_eq!(&output[..], expected);
/// ```
pub fn key_to_base32_uppercase<T: AsRef<[u8]> + Zeroize>(mut key: T) -> String {
    let output = BASE32_NOPAD.encode(key.as_ref());
    key.zeroize();
    output
}

/// Write key bytes to a base32-encoded String in lowercase (Not a standard base32).
/// # Example
/// ```
/// use totp_rfc6238::oath_uri::key_to_base32_lowercase;
/// let expected = "gezdgnbvgy3tqojqebaweqykmrsum";
///
/// let input = [
///     b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b' ', b'A', b'b', b'C', b'\n',
///     b'd', b'e', b'F',
/// ];
/// let output = key_to_base32_lowercase(input);
/// assert_eq!(&output[..], expected);
/// ```
pub fn key_to_base32_lowercase<T: AsRef<[u8]> + Zeroize>(key: T) -> String {
    let mut uppercase = key_to_base32_uppercase(key);
    let output = uppercase.to_ascii_lowercase();
    uppercase.zeroize();
    output
}
