//! This library is for generating Time-based One-time Password (TOTP)
//! codes/tokens, which is defined in [RFC 6238](https://tools.ietf.org/html/rfc6238).
//!
//! Features of this crate:
//! * Both low-level and high-level APIs are provided.
//! * The length of the codes, the initial counter time (T0), update time
//!   interval (period) and hash algorithm are configurable.
//! * HMAC algorithms are implemented by [RustCrypto](https://github.com/RustCrypto) or [ring](https://crates.io/crates/ring).
//! * Read or write "[Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)"
//!   (URIs start with `otpauth://totp/`) (the `oathuri` feature gate).
//! * Read or write `key` from base32-encoded string (the `oathuri` feature
//!   gate).
//!
//! Note: This implementation does **NOT** consider the time earlier than the
//! [Unix epoch (`1970-01-01T00:00:00Z`)](https://en.wikipedia.org/wiki/Unix_time).
//!
//! See [`high_level::TotpGenerator`] for an example.
//!
//! ----
//! Features that may be related to but **not** implemented in this crate:
//! * Read or write QR codes.
pub mod high_level;
pub mod low_level;

#[cfg(feature = "oathuri")]
pub mod oath_uri;

pub use high_level::TotpGenerator;
pub use low_level::HashAlgorithm;
