//! Read or write URIs start with `otpauth://totp/`.
//!
//! This module requires `oathuri` feature gate:
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! totp_rfc6238 = { version = "0.4", features = [ "oathuri" ]}
//! ```
//!
//! The functions and methods in this module will automatically try to
//! overwrite the key-related memory areas that are no longer used with zeros
//! before being released. But this operation is only a best effort. There is
//! no guarantee that any memory area that may have touched the key byte is
//! safely cleared. Because some other crates called in this process may not
//! consider this aspect. It may also be our negligence in writing code. If you
//! have suggestions for improvement, welcome to open a [Pull Request](https://github.com/KaneGreen/totp_rfc6238/pulls).
//!
//! # Note
//! This URI format is refering to
//! [https://github.com/google/google-authenticator/wiki/Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
//! And only TOTP is implemented in this crate.
//!
//! Since the Unix timestamp of the initial counter time T0 is not defined in
//! the URI, this module will always set **T0 to the default value** of
//! [RFC 6238 Section 4](https://tools.ietf.org/html/rfc6238#section-4).

use crate::high_level::{TotpBuilder, TotpGenerator};
use crate::low_level::HashAlgorithm;
use data_encoding::{DecodeError, BASE32_NOPAD};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::HashMap;
use std::mem;
use url::{ParseError, Url};
use zeroize::Zeroize;

/// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURI
const CHARS_NEED_ESCAPE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Types of errors that may occur.
#[derive(Debug)]
pub enum OathUriError {
    Base32Error(DecodeError),
    UrlError(ParseError),
    IntegerError(core::num::ParseIntError),
    EncodingError(core::str::Utf8Error),
    OtpTypeError(&'static str),
    LabelError(&'static str),
    ParameterError(&'static str),
}
impl From<DecodeError> for OathUriError {
    fn from(x: DecodeError) -> Self {
        OathUriError::Base32Error(x)
    }
}
impl From<ParseError> for OathUriError {
    fn from(x: ParseError) -> Self {
        OathUriError::UrlError(x)
    }
}
impl From<core::num::ParseIntError> for OathUriError {
    fn from(x: core::num::ParseIntError) -> Self {
        OathUriError::IntegerError(x)
    }
}
impl From<core::str::Utf8Error> for OathUriError {
    fn from(x: core::str::Utf8Error) -> Self {
        OathUriError::EncodingError(x)
    }
}
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
pub fn key_from_base32(mut encoded: String) -> Result<Vec<u8>, OathUriError> {
    let mut tmp = encoded.to_ascii_uppercase();
    encoded.zeroize();
    let output = BASE32_NOPAD.decode(tmp.as_bytes());
    tmp.zeroize();
    output.map_err(OathUriError::from)
}

/// Write key bytes to a base32-encoded String in uppercase.
///
/// # Example
/// ```
/// use totp_rfc6238::oath_uri::key_to_base32_uppercase;
/// let expected = "GEZDGNBVGY3TQOJQEBAWEQYKMRSUM";
///
/// let input = [
///     b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
///     b' ', b'A', b'b', b'C', b'\n', b'd', b'e', b'F',
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
///     b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
///     b' ', b'A', b'b', b'C', b'\n', b'd', b'e', b'F',
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

/// This struct stores the key bytes, the issuer and account name.
///
/// The key bytes will automatically be overwritten with zeros when the struct
/// is dropped.
///
/// # Example
/// ```
/// use totp_rfc6238::oath_uri::KeyInfo;
/// // Create a new KeyInfo
/// let example_key = vec![
///     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110_u8,
/// ];
/// let mut keyinfo = KeyInfo::new(example_key);
/// keyinfo.issuer = "Example".to_string();
/// keyinfo.account = "noreplay@example.com".to_string();
///
/// // Get a reference of the key
/// let key_ref = keyinfo.borrow_key();
/// assert_eq!(
///     key_ref,
///     &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110_u8,]
/// )
/// ```
pub struct KeyInfo {
    pub issuer: String,
    pub account: String,
    // the `key`
    secret: Vec<u8>,
}
impl Drop for KeyInfo {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl KeyInfo {
    /// Immutably borrows the key bytes from this struct.
    pub fn borrow_key(&self) -> &[u8] {
        &self.secret
    }
    /// Create this struct from the key bytes. The issuer and account name are empty now.
    pub fn new(key: Vec<u8>) -> Self {
        KeyInfo {
            secret: key,
            issuer: String::new(),
            account: String::new(),
        }
    }
}
/// This struct provides reading and writing TOTP URIs.
pub struct TotpUri {
    issuer: String,
    account: String,
    algorithm: HashAlgorithm,
    // the `key`
    secret: Vec<u8>,
    // the `digit`
    digits: usize,
    // the `step`
    period: u64,
}
impl Drop for TotpUri {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl TotpUri {
    /// Read TOTP informations and configurations from the TOTP URIs.
    ///
    /// # Example
    /// ```
    /// use totp_rfc6238::oath_uri::TotpUri;
    /// use totp_rfc6238::HashAlgorithm;
    ///
    /// let uri = String::from("otpauth://totp/Example:noreply@example.com?secret=OOP3SKVZ4AWKHS7RSSJNR3LKI5LA4GUE&issuer=Example");
    /// let totp = TotpUri::from_uri(uri).unwrap();
    /// let (builder, keyinfo) = totp.into_builder_and_keyinfo().unwrap();
    ///
    /// assert_eq!(builder.get_digit(), 6);
    /// assert_eq!(builder.get_step(), 30);
    /// assert_eq!(builder.get_t0(), 0);
    /// assert_eq!(builder.get_hash_algorithm(), HashAlgorithm::SHA1);
    /// assert_eq!(&keyinfo.issuer, "Example");
    /// assert_eq!(&keyinfo.account, "noreply@example.com");
    /// assert_eq!(
    ///     keyinfo.borrow_key(),
    ///     b"\x73\x9f\xb9\x2a\xb9\xe0\x2c\xa3\xcb\xf1\x94\x92\xd8\xed\x6a\x47\x56\x0e\x1a\x84"
    /// );
    /// ```
    pub fn from_uri(mut uri: String) -> Result<Self, OathUriError> {
        let parsed = Url::parse(&uri)?;

        match parsed.host_str() {
            Some(otp) => {
                if otp.to_ascii_lowercase() != "totp" {
                    return Err(OathUriError::OtpTypeError(
                        "Only totp is the supported OTP type",
                    ));
                }
            }
            None => return Err(OathUriError::OtpTypeError("No OTP type in given URI")),
        }

        let parameters = parsed.query_pairs();
        let mut map_parameters = HashMap::new();
        for (k, v) in parameters {
            map_parameters.insert(k.to_ascii_lowercase(), v);
        }

        let parameter_secret = match map_parameters.get("secret") {
            Some(x) => key_from_base32(x.to_string())?,
            None => {
                return Err(OathUriError::ParameterError(
                    "Secret: no `secret` parameter in given URI",
                ))
            }
        };

        let parameter_digits = match map_parameters.get("digits") {
            Some(x) => x.parse::<usize>()?,
            None => 6,
        };
        let parameter_period = match map_parameters.get("period") {
            Some(x) => x.parse::<u64>()?,
            None => 30,
        };
        let parameter_algorithm = match map_parameters.get("algorithm") {
            Some(x) => match x.to_ascii_uppercase().as_ref() {
                "SHA1" | "SHA-1" => HashAlgorithm::SHA1,
                "SHA256" | "SHA-256" => HashAlgorithm::SHA256,
                "SHA512" | "SHA-512" => HashAlgorithm::SHA512,
                _ => {
                    return Err(OathUriError::ParameterError(
                        "Hash Algorithm: only SHA-1, SHA-256, SHA-512 are supported.",
                    ))
                }
            },
            None => HashAlgorithm::SHA1,
        };

        let parameter_issuer = map_parameters.get("issuer");

        let label = percent_decode_str(parsed.path()).decode_utf8()?;
        let mut label_iter = label[1..].split(':');
        let l_first = label_iter.next().ok_or(OathUriError::LabelError(
            "Account Name: no `account` label in given URI",
        ))?;
        let label_second = label_iter.next();

        let real_issuer;
        let real_account;
        match (parameter_issuer, label_second) {
            (Some(p), Some(l_second)) => {
                if p != l_first {
                    return Err(OathUriError::LabelError(
                        "`issuer` in label and parameters are inconsistent in given URI",
                    ));
                }
                real_issuer = p.to_string();
                real_account = l_second.to_string();
            }
            (Some(p), None) => {
                real_issuer = p.to_string();
                real_account = l_first.to_string();
            }
            (None, Some(l_second)) => {
                real_issuer = l_first.to_string();
                real_account = l_second.to_string();
            }
            (None, None) => {
                return Err(OathUriError::ParameterError(
                    "Issuer: no `issuer` parameter in given URI",
                ))
            }
        }

        let output = TotpUri {
            secret: parameter_secret,
            issuer: real_issuer,
            account: real_account,
            algorithm: parameter_algorithm,
            digits: parameter_digits,
            period: parameter_period,
        };
        uri.zeroize();
        Ok(output)
    }
    /// Write the infomations and configurations to the TOTP URIs.
    ///
    /// # Example
    /// ```
    /// use totp_rfc6238::high_level::TotpGenerator;
    /// use totp_rfc6238::oath_uri::{KeyInfo, TotpUri};
    /// use totp_rfc6238::HashAlgorithm;
    ///
    /// let expected = "otpauth://totp/Example:no-reply@example.com?secret=IFBEGRCFIZDUQSKKGAYTEMZUGU3DOOBZ&issuer=Example&algorithm=SHA512&digits=8&period=60";
    ///
    /// let key = vec![
    ///     b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J',
    ///     b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
    /// ];
    /// // Create a non-standard TOTP code generator: 8-digit, updating every 60
    /// // seconds, starting at "Jan 01 1970 00:16:40 UTC", using HMAC-SHA512.
    /// let builder = TotpGenerator::new()
    ///     .set_digit(8)
    ///     .unwrap()
    ///     .set_step(60)
    ///     .unwrap()
    ///     .set_t0(1000)
    ///     .set_hash_algorithm(HashAlgorithm::SHA512);
    ///
    /// let mut keyinfo = KeyInfo::new(key);
    /// keyinfo.issuer = "Example".to_string();
    /// keyinfo.account = "no-reply@example.com".to_string();
    ///
    /// let totpuri = TotpUri::from_builder_and_keyinfo(builder, keyinfo);
    /// assert_eq!(&totpuri.into_uri(), expected);
    /// ```
    pub fn into_uri(self) -> String {
        let mut uri = Url::parse("otpauth://totp/").unwrap();
        // These two are unnecessary:
        // uri.set_scheme("otpauth").unwrap();
        // uri.set_host(Some("totp")).unwrap();
        let path = format!(
            "{}:{}",
            utf8_percent_encode(&self.issuer, CHARS_NEED_ESCAPE).to_string(),
            utf8_percent_encode(&self.account, CHARS_NEED_ESCAPE).to_string(),
        );
        uri.set_path(&path);

        uri.query_pairs_mut().clear();

        {
            let mut encoded_secret = BASE32_NOPAD.encode(&self.secret);
            uri.query_pairs_mut()
                .append_pair("secret", encoded_secret.as_str());
            encoded_secret.zeroize();
        }

        uri.query_pairs_mut().append_pair("issuer", &self.issuer);

        let default = TotpGenerator::new();
        if self.algorithm != default.get_hash_algorithm() {
            uri.query_pairs_mut()
                .append_pair("algorithm", self.algorithm.as_str());
        }
        if self.digits != default.get_digit() {
            uri.query_pairs_mut()
                .append_pair("digits", &self.digits.to_string());
        }
        if self.period != default.get_step() {
            uri.query_pairs_mut()
                .append_pair("period", &self.period.to_string());
        }
        uri.into()
    }
    /// Create an instance of this struct From [`TotpBuilder`] and [`KeyInfo`].
    ///
    /// # Example
    /// See the example of [`TotpUri::into_uri`].
    pub fn from_builder_and_keyinfo(builder: TotpBuilder, mut keyinfo: KeyInfo) -> Self {
        let mut output = TotpUri {
            issuer: String::new(),
            account: String::new(),
            secret: Vec::new(),
            algorithm: builder.get_hash_algorithm(),
            digits: builder.get_digit(),
            period: builder.get_step(),
        };
        mem::swap(&mut output.secret, &mut keyinfo.secret);
        mem::swap(&mut output.issuer, &mut keyinfo.issuer);
        mem::swap(&mut output.account, &mut keyinfo.account);
        output
    }
    /// Convert this struct to [`TotpBuilder`] and [`KeyInfo`].
    ///
    /// # Example
    /// See the example of [`TotpUri::from_uri`].
    pub fn into_builder_and_keyinfo(mut self) -> Result<(TotpBuilder, KeyInfo), OathUriError> {
        let builder = TotpGenerator::new()
            .set_hash_algorithm(self.algorithm)
            .set_step(self.period)
            .or(Err(OathUriError::ParameterError(
                "Period: the `period` parameter in given URI is invalid",
            )))?
            .set_digit(self.digits)
            .or(Err(OathUriError::ParameterError(
                "Digits: the `digits` parameter in given URI is invalid",
            )))?;
        let mut info = KeyInfo::new(Vec::new());
        mem::swap(&mut info.secret, &mut self.secret);
        mem::swap(&mut info.issuer, &mut self.issuer);
        mem::swap(&mut info.account, &mut self.account);
        Ok((builder, info))
    }
}
