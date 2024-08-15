//! Low-level APIs for TOTP code generation.
//!
//! Don't use these APIs directly unless you know exactly what you are doing.

use std::convert::TryInto;
use std::iter::FromIterator;

/// Hash functions for HMAC supported in
/// [RFC 6238 Section 1.2](https://tools.ietf.org/html/rfc6238#section-1.2).
///
/// So far, only SHA-1, SHA-256 and SHA-512 are supported.
///
/// # Example
/// ```
/// use totp_rfc6238::HashAlgorithm;
///
/// let a = HashAlgorithm::SHA256;
/// // This `HashAlgorithm` can be converted from `str` case-insensitively.
/// let b = HashAlgorithm::from("SHA-256");
/// let c: HashAlgorithm = "sha256".into();
///
/// assert_eq!(a, b);
/// assert_eq!(a, c);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl<T: AsRef<str>> From<T> for HashAlgorithm {
    fn from(x: T) -> Self {
        let t: &str = x.as_ref();
        match t.to_ascii_uppercase().as_ref() {
            "SHA1" | "SHA-1" => HashAlgorithm::SHA1,
            "SHA256" | "SHA-256" => HashAlgorithm::SHA256,
            "SHA512" | "SHA-512" => HashAlgorithm::SHA512,
            _ => panic!("{} is not a acceptable hash algorithm", t),
        }
    }
}
impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::SHA1 => "SHA1",
            HashAlgorithm::SHA256 => "SHA256",
            HashAlgorithm::SHA512 => "SHA512",
        }
    }
}

/// The counter as a time factor for TOTP defined in [RFC 6238 Section 4].
///
/// Arguments:
/// In this function, 64-bit unsigned integer (u64) is used to store the Unix
/// timestamp.
/// * `current`: Unix timestamp of the current time.
/// * `t0`: Unix timestamp of the initial counter time T0 (default value in
///   [RFC 6238 Section 4] is `0`).
/// * `step`: The time step in seconds (default value in [RFC 6238 Section 4]
///   is `30`).
///
/// Return:
/// * an array of 8 bytes contains the counter value, which represents the
///   number of time steps between the initial counter time T0 and the current
///   Unix time.
///
/// # Panics
/// Panics if `current` is less than `t0` or `step` is zero.
///
/// # Example
/// ```
/// use totp_rfc6238::low_level::time_based_counter_bytes;
///
/// // 59 is the Unix timestamp of "1970-01-01 00:00:59 UTC"
/// let output = time_based_counter_bytes(59, 0, 30);
///
/// assert_eq!(output, 1_u64.to_be_bytes());
/// ```
/// [RFC 6238 Section 4]:https://tools.ietf.org/html/rfc6238#section-4
#[inline(always)]
pub fn time_based_counter_bytes(current: u64, t0: u64, step: u64) -> [u8; 8] {
    time_based_counter_number(current, t0, step).to_be_bytes()
}
#[inline(always)]
pub(crate) fn time_based_counter_number(current: u64, t0: u64, step: u64) -> u64 {
    assert!(current >= t0);
    (current - t0) / step
}

/// Compute the HMAC bytes for given bytes.
///
/// Arguments:
/// * `msg`: bytes of the message.
/// * `key`: bytes of the key.
/// * `hash_type`: specify the hash function using the [`HashAlgorithm`] enum.
///
/// Return:
/// * a [collection](https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.collect)
///   of HMAC bytes transformed from an iterator.
///
/// # Example
/// ```
/// use totp_rfc6238::{low_level::hmac_sha, HashAlgorithm};
/// // these test vectors come form https://tools.ietf.org/html/rfc4231.html#section-4.2
/// let expected = &[
///     0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8,
///     0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00,
///     0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
///     0xcf, 0xf7_u8,
/// ];
///
/// let m = b"Hi There";
/// let k = &[0x0b_u8; 20];
/// let output: Vec<_> = hmac_sha(m, k, HashAlgorithm::SHA256);
///
/// assert_eq!(&output[..], expected)
/// ```
///
/// # Note
/// It would be better thar the size of the key is the same as the output
/// length of the hash function, based on the recommendation in
/// [RFC 2104 Section 3](https://tools.ietf.org/html/rfc2104#section-3).
/// However, shorter or longer keys are allowed. For more information on
/// handling such keys, please refer to the
/// [document of `ring::hmac::Key::new`](https://docs.rs/ring/latest/ring/hmac/struct.Key.html#method.new).
#[cfg(feature = "ring")]
pub fn hmac_sha<T: FromIterator<u8>>(msg: &[u8], key: &[u8], hash_type: HashAlgorithm) -> T {
    use ring::hmac;
    let hasher = match hash_type {
        HashAlgorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::SHA256 => hmac::HMAC_SHA256,
        HashAlgorithm::SHA512 => hmac::HMAC_SHA512,
    };
    let s_key = hmac::Key::new(hasher, key);
    let mut s_ctx = hmac::Context::with_key(&s_key);
    s_ctx.update(msg.as_ref());
    let tag = s_ctx.sign();
    tag.as_ref().iter().cloned().collect()
}

/// Compute the HMAC bytes for given bytes.
///
/// Arguments:
/// * `msg`: bytes of the message.
/// * `key`: bytes of the key.
/// * `hash_type`: specify the hash function using the [`HashAlgorithm`] enum.
///
/// Return:
/// * a [collection](https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.collect)
///   of HMAC bytes transformed from an iterator.
///
/// # Example
/// ```
/// use totp_rfc6238::{low_level::hmac_sha, HashAlgorithm};
/// // these test vectors come form https://tools.ietf.org/html/rfc4231.html#section-4.2
/// let expected = &[
///     0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8,
///     0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00,
///     0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
///     0xcf, 0xf7_u8,
/// ];
///
/// let m = b"Hi There";
/// let k = &[0x0b_u8; 20];
/// let output: Vec<_> = hmac_sha(m, k, HashAlgorithm::SHA256);
///
/// assert_eq!(&output[..], expected)
/// ```
///
/// # Note
/// It would be better thar the size of the key is the same as the output
/// length of the hash function, based on the recommendation in
/// [RFC 2104 Section 3](https://tools.ietf.org/html/rfc2104#section-3).
/// However, shorter or longer keys are allowed. For more information on
/// handling such keys, please refer to the
/// [document of `ring::hmac::Key::new`](https://docs.rs/ring/latest/ring/hmac/struct.Key.html#method.new).
#[cfg(feature = "rustcrypto")]
pub fn hmac_sha<T: FromIterator<u8>>(msg: &[u8], key: &[u8], hash_type: HashAlgorithm) -> T {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};
    match hash_type {
        HashAlgorithm::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(msg);
            let result = mac.finalize();
            result.into_bytes().iter().cloned().collect()
        }
        HashAlgorithm::SHA256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(msg);
            let result = mac.finalize();
            result.into_bytes().iter().cloned().collect()
        }
        HashAlgorithm::SHA512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(msg);
            let result = mac.finalize();
            result.into_bytes().iter().cloned().collect()
        }
    }
}
/// The `Truncate` function (internal step): extract 31 bits from the HMAC
/// bytes and truncate the the lowest decimal digits.
///
/// Usage: `truncate_to_string(truncate_usize(hmac_result, digit), digit)` is
/// equal to `truncate(hmac_result, digit)`.
///
/// # Example
/// ```
/// use totp_rfc6238::low_level::truncate_usize;
/// // these test vectors come form https://tools.ietf.org/html/rfc4226#section-5.4
/// let expected = 872921_usize;
///
/// let h = &[
///     0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85,
///     0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a_u8,
/// ];
/// let d = 6_usize;
/// let output = truncate_usize(h, d);
///
/// assert_eq!(output, expected);
/// ```
pub fn truncate_usize(hmac_result: &[u8], digit: usize) -> usize {
    let offset = (0x0f & hmac_result.last().expect("the `hmac_result` is empty")) as usize;
    let bin_code =
        u32::from_be_bytes(hmac_result[offset..=offset + 3].try_into().unwrap()) as usize;
    (bin_code & 0x7fff_ffff) % 10_usize.pow(digit as u32)
}

/// The `Truncate` function (internal step): convert and pad with leading zeros
/// the number (uszie) into String.
///
/// Usage: `truncate_to_string(truncate_usize(hmac_result, digit), digit)` is
/// equal to `truncate(hmac_result, digit)`.
///
/// # Example
/// ```
/// use totp_rfc6238::low_level::truncate_to_string;
///
/// let a = truncate_to_string(12345_usize, 8);
///
/// assert_eq!(&a[..], "00012345");
/// ```
pub fn truncate_to_string(code: usize, digit: usize) -> String {
    let origin = code.to_string();
    let padding = digit.saturating_sub(origin.len());
    let mut result = String::new();
    while result.len() < padding {
        result.push('0');
    }
    result.push_str(origin.as_str());
    result
}
/// The `Truncate` function defined in
/// [RFC 4226 Section 5.3](https://tools.ietf.org/html/rfc4226#section-5.3):
/// extract 31 bits from the HMAC bytes and truncate the the lowest decimal
/// digits to a String.
///
/// Arguments:
/// * `hmac_result`: bytes of the HMAC output.
/// * `digit`: the length of TOTP code.
///
/// Return:
/// * a String that contains the TOTP code.
///
/// # Panics
/// Panics if `digit` is zero.
///
/// # Example
/// ```
/// use totp_rfc6238::low_level::truncate;
/// // these test vectors come form https://tools.ietf.org/html/rfc4226#section-5.4
/// let expected = "872921";
///
/// let h = &[
///     0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85,
///     0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a_u8,
/// ];
/// let d = 6_usize;
/// let output = truncate(h, d);
///
/// assert_eq!(&output[..], expected);
/// ```
#[inline]
pub fn truncate(hmac_result: &[u8], digit: usize) -> String {
    assert_ne!(digit, 0);
    truncate_to_string(truncate_usize(hmac_result, digit), digit)
}

#[cfg(test)]
mod tests {
    const TIMES: [u64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];
    #[test]
    fn time_based_counter_bytes_works() {
        const COUNTS: [u64; 6] = [
            1, 0x023523ec, 0x023523ed, 0x0273ef07, 0x03f940aa, 0x27bc86aa,
        ];
        for (&time, count) in TIMES.iter().zip(COUNTS.iter()) {
            assert_eq!(
                super::time_based_counter_bytes(time, 0, 30),
                count.to_be_bytes()
            );
        }
    }
    #[test]
    fn time_based_counter_bytes_extended_tests() {
        use super::time_based_counter_bytes;
        assert_eq!(time_based_counter_bytes(0, 0, 10), 0_u64.to_be_bytes());
        assert_eq!(time_based_counter_bytes(1, 0, 10), 0_u64.to_be_bytes());
        assert_eq!(time_based_counter_bytes(60, 0, 30), 2_u64.to_be_bytes());
        assert_eq!(time_based_counter_bytes(61, 0, 30), 2_u64.to_be_bytes());
    }
    #[test]
    #[should_panic]
    fn time_based_counter_bytes_panic() {
        assert_eq!(
            super::time_based_counter_bytes(59, 100, 30),
            2_u64.to_be_bytes()
        );
    }
    #[test]
    fn rfc6238_vectors_works() {
        const RESULTS: [(&str, &str, &str); 6] = [
            ("94287082", "46119246", "90693936"),
            ("07081804", "68084774", "25091201"),
            ("14050471", "67062674", "99943326"),
            ("89005924", "91819424", "93441116"),
            ("69279037", "90698825", "38618901"),
            ("65353130", "77737706", "47863826"),
        ];
        let key_sha1: &[u8; 20] = b"12345678901234567890";
        let key_sha256 = [&key_sha1[..], &key_sha1[..12]].concat();
        let key_sha512 = [&key_sha1[..], &key_sha1[..], &key_sha1[..], &key_sha1[..4]].concat();
        for (&time, result) in TIMES.iter().zip(RESULTS.iter()) {
            assert_eq!(generate_totp(time, &key_sha1[..], "SHA-1"), result.0);
            assert_eq!(generate_totp(time, &key_sha256[..], "SHA256"), result.1);
            assert_eq!(generate_totp(time, &key_sha512[..], "sha512"), result.2);
        }
    }
    fn generate_totp(time: u64, key: &[u8], h: &str) -> String {
        use super::{hmac_sha, time_based_counter_bytes, truncate};
        let count = time_based_counter_bytes(time, 0, 30);
        let mac: Vec<_> = hmac_sha(&count, key, h.into());
        truncate(&mac[..], 8)
    }
}
