//! Read or write URIs start with `otpauth://totp/`.
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

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

pub enum OathUriError {
    Base32Error(DecodeError),
    UrlError(ParseError),
    IntegerError(std::num::ParseIntError),
    EncodingError(core::str::Utf8Error),
    OtpTypeError(String),
    LabelError(String),
    ParameterError(String),
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
impl From<std::num::ParseIntError> for OathUriError {
    fn from(x: std::num::ParseIntError) -> Self {
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
    pub fn borrow_key(&self) -> &[u8] {
        &self.secret
    }
    pub fn new(key: Vec<u8>) -> Self {
        KeyInfo {
            secret: key,
            issuer: String::new(),
            account: String::new(),
        }
    }
}
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
    pub fn from_uri(mut uri: String) -> Result<Self, OathUriError> {
        let parsed = Url::parse(&uri)?;

        match parsed.host_str() {
            Some(otp) => {
                if otp.to_ascii_lowercase() != "totp" {
                    return Err(OathUriError::OtpTypeError(format!(
                        "`{}` is not a supported OTP type",
                        otp
                    )));
                }
            }
            None => {
                return Err(OathUriError::OtpTypeError(
                    "No OTP type in given URI".to_string(),
                ))
            }
        }

        let parameters = parsed.query_pairs();
        let mut map_parameters = HashMap::new();
        for (k, v) in parameters {
            map_parameters.insert(k, v);
        }

        let parameter_secret = match map_parameters.get("secret") {
            Some(x) => key_from_base32(x.to_string())?,
            None => {
                return Err(OathUriError::ParameterError(
                    "No `secret` parameter in given URI".to_string(),
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
                    return Err(OathUriError::ParameterError(format!(
                        "`{}` is not a supported hash algorithm",
                        x
                    )))
                }
            },
            None => HashAlgorithm::SHA1,
        };

        let parameter_issuer = map_parameters.get("issuer");

        let label = percent_decode_str(parsed.path()).decode_utf8()?;
        let mut label_iter = label[1..].split(':');
        let l_first = label_iter.next().ok_or(OathUriError::LabelError(
            "No `account` label in given URI".to_string(),
        ))?;
        let label_second = label_iter.next();

        let real_issuer;
        let real_account;
        match (parameter_issuer, label_second) {
            (Some(p), Some(l_second)) => {
                if p != l_first {
                    return Err(OathUriError::LabelError(
                        "`issuer` in label and parameters are inconsistent in given URI"
                            .to_string(),
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
                    "No `issuer` parameter in given URI".to_string(),
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
    /// assert_eq!(&totpuri.to_uri(), expected);
    /// ```
    pub fn to_uri(self) -> String {
        let mut uri = Url::parse("otpauth://totp/").unwrap();
        // These two are unnecessary:
        // uri.set_scheme("otpauth").unwrap();
        // uri.set_host(Some("totp")).unwrap();
        let path = format!(
            "{}:{}",
            utf8_percent_encode(&self.issuer, FRAGMENT).to_string(),
            utf8_percent_encode(&self.account, FRAGMENT).to_string(),
        );
        uri.set_path(&path);

        let default = TotpGenerator::new();
        uri.query_pairs_mut().clear();
        let mut encoded_secret = BASE32_NOPAD.encode(&self.secret);
        uri.query_pairs_mut()
            .append_pair("secret", encoded_secret.as_str());
        encoded_secret.zeroize();
        uri.query_pairs_mut().append_pair("issuer", &self.issuer);
        if default.get_hash_algorithm() != self.algorithm {
            uri.query_pairs_mut()
                .append_pair("algorithm", self.algorithm.as_str());
        }
        if default.get_digit() != self.digits {
            uri.query_pairs_mut()
                .append_pair("digits", &self.digits.to_string());
        }
        if default.get_step() != self.period {
            uri.query_pairs_mut()
                .append_pair("period", &self.period.to_string());
        }
        uri.into_string()
    }
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
    pub fn to_builder_and_keyinfo(mut self) -> Result<(TotpBuilder, KeyInfo), OathUriError> {
        let builder = TotpGenerator::new()
            .set_hash_algorithm(self.algorithm)
            .set_step(self.period)
            .or(Err(OathUriError::ParameterError(
                "The `period` parameter in given URI is invalid".to_string(),
            )))?
            .set_digit(self.digits)
            .or(Err(OathUriError::ParameterError(
                "The `digits` parameter in given URI is invalid".to_string(),
            )))?;
        let mut info = KeyInfo::new(Vec::new());
        mem::swap(&mut info.secret, &mut self.secret);
        mem::swap(&mut info.issuer, &mut self.issuer);
        mem::swap(&mut info.account, &mut self.account);
        Ok((builder, info))
    }
}
