# Changelog
## v0.6.1
* Improved the documentation. No actual code changes.
## v0.6.0
* Using RustCrypto's SHA implementation by default, instead of Ring.
* Improved the documentation.
## v0.5.3
* Extra traits implemented.
## v0.5.2
(unreleased)
## v0.5.1
* Update dependencies.
## v0.5.0
* **API changed**: Improved error handling.
## v0.4.2
* Improved the documentation. No actual code changes.
## v0.4.1
* The method `oath_uri::TotpUri::from_uri` now are case-insensitive to
  parameter names in URIs.
## v0.4.0
* **API changed**: function names of all `to_*` methods in `oath_uri::TotpUri`
  changed to `into_*`.
* **API changed**: data type of `oath_uri::OathUriError` has changed.
## v0.3.1
* Improved the documentation. No actual code changes.
## v0.3.0
* The escape characters in the URI has been changed to be consistent with the
  encodeURI() function. This may cause incompatibility with previous versions.
## v0.2.0
* New feature "Read or write Key Uri Format".
* New feature "Read or write key from base32-encoded string".
## v0.1.0
* The first release: minimum viable product.
