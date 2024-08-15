# totp_rfc6238
A rust crate for generating TOTP codes (tokens) defined in [RFC 6238](https://tools.ietf.org/html/rfc6238).

[![crates.io](https://img.shields.io/crates/v/totp_rfc6238.svg)](https://crates.io/crates/totp_rfc6238)
[![docs.rs](https://docs.rs/totp_rfc6238/badge.svg)](https://docs.rs/totp_rfc6238)
[![Rust-test](https://github.com/KaneGreen/totp_rfc6238/actions/workflows/rust-test.yml/badge.svg?branch=master&event=push)](https://github.com/KaneGreen/totp_rfc6238/actions/workflows/rust-test.yml)

## Features of this crate
* Both low-level and high-level APIs are provided.
* The length of the codes, the initial counter time (T0), update time interval
(period) and hash algorithm are configurable.
* HMAC algorithms are implemented by [ring](https://crates.io/crates/ring).
* Read or write "[Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)"
(URIs start with `otpauth://totp/`) (the `oathuri` feature gate).
* Read or write `key` from base32-encoded string (the `oathuri` feature gate).

### Select SHA implementation
* using [RustCrypto](https://github.com/RustCrypto/MACs/tree/master/hmac)'s implementation (default)
    ```toml
    [dependencies]
    totp_rfc6238 = "0.6"
    ```
* using [Ring](https://github.com/briansmith/ring)'s implementation
    ```toml
    [dependencies]
    totp_rfc6238 = { version = "0.6", default-features = false, features = ["ring"] }
    ```

### Note
This implementation does **NOT** consider the time earlier than the
[Unix epoch (`1970-01-01T00:00:00Z`)](https://en.wikipedia.org/wiki/Unix_time).

## Example
```rust
use totp_rfc6238::{HashAlgorithm, TotpGenerator};
fn main() {
    // Create a standard TOTP code generator: 6-digit, updating every
    // 30 seconds, starting at "Jan 01 1970 00:00:00 UTC", using HMAC-SHA1.
    let mut totp_generator = TotpGenerator::new().build();

    // Assuming you read the key from some secure area
    let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/";

    let output1 = totp_generator.get_code(key);
    println!("Your TOTP code for current time is: {}", output1);

    let output2 = totp_generator.get_next_update_time().unwrap();
    println!("Next update will be at the unix timestamp of {}", output2);

    let output3 = totp_generator.get_code_window(key, -4..=4).unwrap();
    println!("Codes for 2 minutes earlier or later are:");
    for i in output3 {
        println!("  {}", i);
    }

    // You can also create a non-standard TOTP code generator: 8-digit,
    // updating every 90 seconds, starting at "Jan 01 1970 00:16:42 UTC",
    // using HMAC-SHA512.
    let mut another_totp_generator = TotpGenerator::new()
        .set_digit(8).unwrap()
        .set_step(90).unwrap()
        .set_t0(16 * 60 + 42)
        .set_hash_algorithm(HashAlgorithm::SHA512)
        .build();

    let output4 = another_totp_generator.get_code(key);
    println!("Your non-standard TOTP code for current time is: {}", output4);
}
```

## Changelog
See [here](./CHANGELOG.md).
### Incompatible API breaking changes
The version number lower than `1.0.0` should be regarded as an unstable version
of the API. Therefore, some version updates may contain incompatible API
changes. Please refer to the following when changing the dependent version.
* v0.5.2 (unreleased) -> v0.5.3: `oath_uri::TotpUri` and `oath_uri::KeyInfo`
implemented the `Debug` trait in version 0.5.2, but this was removed in 0.5.3.
(only affects the `oathuri` feature)
* v0.4.2 -> v0.5.0: The data types of errors has changed. (only affects the
`oathuri` feature)
* v0.3.1 -> v0.4.0: The data types of errors and function names has changed.
(only affects the `oathuri` feature)
* v0.2.0 -> v0.3.0: In the percent-encoding, the characters that need to be
escaped have changed. (only affects the `oathuri` feature)

## Warning
The codes of this crate has not been audited.

## Features that may be related to but NOT implemented in this crate
* Read or write QR codes.

## License
This tool is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0), with portions covered by various
BSD-like licenses.  
See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

### Contribution
1. Any contribution intentionally submitted for inclusion in totp_rfc6238 by
  you, as defined in the Apache-2.0 license, shall be dual licensed as above,
  without any additional terms or conditions.
2. Pull requests are always welcome.