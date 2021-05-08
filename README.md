# totp_rfc6238
A rust crate for generating TOTP codes (tokens) defined in [RFC 6238](https://tools.ietf.org/html/rfc6238).

## Features of this crate
* Both low-level and high-level APIs are provided.
* The length of the codes, the initial counter time (T0), update time interval
(period) and hash algorithm are configurable.
* HMAC algorithms are implemented by [ring](https://crates.io/crates/ring).
* Read or write "[Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)"
(URIs start with `otpauth://totp/`) (the `oathuri` feature gate).
* Read or write `key` from base32-encoded string (the `oathuri` feature gate).

### Note
This implementation does **NOT** consider the time earlier than the
[Unix epoch (`1970-01-01T00:00:00Z`)](https://en.wikipedia.org/wiki/Unix_time).

## Example
```rust
use totp_rfc6238::{HashAlgorithm, TotpGenerator};
fn main() {
    let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/";
    // Create a non-standard TOTP code generator: 8-digit, updating every 60
    // seconds, starting at "Jan 01 1970 00:16:40 UTC", using HMAC-SHA512.
    let mut totp_generator = TotpGenerator::new()
        .set_digit(8).unwrap()
        .set_step(60).unwrap()
        .set_t0(1000)
        .set_hash_algorithm(HashAlgorithm::SHA512)
        .build();
    
    let output1 = totp_generator.get_code(key);
    println!("Your TOTP code for current time is: {}", output1);
    
    let output2 = totp_generator.get_next_update_time().unwrap();
    println!("Next update will be at the unix timestamp of {}", output2);
    
    let output3 = totp_generator.get_code_window(key, -5..=5).unwrap();
    println!("Codes for 5 minutes earlier or later are:");
    for i in output3 {
        println!("  {}", i);
    }
}
```

## Warning
The codes of this crate has not been audited.

## Features that may be related to but NOT implemented in this crate
* Read or write QR codes.

## Contribution
1. Any contribution intentionally submitted for inclusion in openssl-src by
  you, as defined in the Apache-2.0 license, shall be dual licensed as
  above, without any additional terms or conditions.
2. Pull requests are always welcome.

## License
This tool is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0), with portions covered by various
BSD-like licenses.  
See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.
