//! This library is for generating TOTP codes (tokens), which is defined in
//! [RFC 6238](https://tools.ietf.org/html/rfc6238).
//!
//! Features of this crate:
//! * Both low-level and high-level APIs are provided.
//! * The length of the codes, the initial counter time (T0), update time
//! interval (period) and hash algorithm are configurable.
//! * HMAC algorithms are implemented by [ring](https://crates.io/crates/ring).
//!
//! See [`high_level::TotpGenerator`] for an example.
//!
//! ----
//! Features that may be related to but **not** implemented in this crate:
//! * Read or write "[Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)"
//! (URIs start with `otpauth://totp/`).
//! * Read or write `key` from base32-encoded string. (But the crate
//! [data-encoding](https://docs.rs/data-encoding/latest/data_encoding/constant.BASE32_NOPAD.html)
//! may help this)
//! * Read or write QR codes.
pub mod high_level;
pub mod low_level;

pub use high_level::TotpGenerator;
pub use low_level::HashAlgorithm;
