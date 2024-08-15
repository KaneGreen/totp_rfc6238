//! High-level APIs for TOTP code generation.
use crate::low_level::{
    hmac_sha, time_based_counter_bytes, time_based_counter_number, truncate, HashAlgorithm,
};
use std::time::{SystemTime, UNIX_EPOCH};
/// Builder for create an instance of [TotpGenerator]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct TotpBuilder {
    digit: usize,
    step: u64,
    t0: u64,
    hash_algorithm: HashAlgorithm,
}
/// Default value: digit = 6, step = 30, t0 = 0, HashAlgorithm::SHA1
impl Default for TotpBuilder {
    fn default() -> Self {
        TotpBuilder {
            digit: 6,
            step: 30,
            t0: 0,
            hash_algorithm: HashAlgorithm::SHA1,
        }
    }
}
impl TotpBuilder {
    /// Set a new value to the field `step`: the update time interval in seconds.
    ///
    /// If the `value` is non-zero, the update will success and return `Ok`.
    /// Otherwise, the update will fail then return `Err`.
    ///
    /// # Example
    /// ```
    /// use totp_rfc6238::high_level::{TotpBuilder, TotpGenerator};
    ///
    /// let a: TotpBuilder = TotpGenerator::new();
    /// assert_eq!(a.get_step(), 30);
    ///
    /// // updating with a non-zero value will success
    /// let b: TotpBuilder = a.set_step(40).unwrap();
    /// assert_eq!(b.get_step(), 40);
    ///
    /// // updating with `0` value will fail
    /// // use `unwrap_or_else` to get the unchanged value
    /// let c: TotpBuilder = b.set_step(0).unwrap_or_else(|x| x);
    /// assert_eq!(c.get_step(), 40);
    /// ```
    pub fn set_step(mut self, value: u64) -> Result<Self, Self> {
        if value != 0 {
            self.step = value;
            Ok(self)
        } else {
            Err(self)
        }
    }
    /// Set a new value to the field `digit`: the length of the TOTP code.
    ///
    /// If the `value` is **greater than 0 and less than 11**, the update will
    /// success and return `Ok`. Otherwise, the update will fail then return
    /// `Err`.  
    /// This is because a 31-bit unsigned integer has a maximum of 10 decimal
    /// digits. In [RFC 4226 Section 5.3](https://tools.ietf.org/html/rfc4226#section-5.3),
    /// the recommended values are 6 ~ 8. But here we give you more choices.
    ///
    /// # Example
    /// ```
    /// use totp_rfc6238::high_level::{TotpBuilder, TotpGenerator};
    ///
    /// let a: TotpBuilder = TotpGenerator::new();
    /// assert_eq!(a.get_digit(), 6);
    ///
    /// // updating with a valid value will success
    /// let b: TotpBuilder = a.set_digit(8).unwrap();
    /// assert_eq!(b.get_digit(), 8);
    ///
    /// // updating with an invalid value will fail
    /// // use `unwrap_or_else` to get the unchanged value
    /// let c: TotpBuilder = b.set_digit(100).unwrap_or_else(|x| x);
    /// assert_eq!(c.get_digit(), 8);
    /// ```
    pub fn set_digit(mut self, value: usize) -> Result<Self, Self> {
        if value > 0 && value <= 10 {
            // max of 31-bit unsigned integer is 10-digit in decimal
            self.digit = value;
            Ok(self)
        } else {
            Err(self)
        }
    }
    /// Set a new value to the field `t0`: the Unix timestamp of the initial
    /// counter time T0.
    pub fn set_t0(mut self, timestamp: u64) -> Self {
        self.t0 = timestamp;
        self
    }
    /// Set a new value to the field `hash_algorithm`.
    pub fn set_hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.hash_algorithm = algorithm;
        self
    }
    /// Use values in this builder to build a [TotpGenerator] instance.
    pub fn build(self) -> TotpGenerator {
        TotpGenerator {
            current: None,
            digit: self.digit,
            step: self.step,
            t0: self.t0,
            hash_algorithm: self.hash_algorithm,
        }
    }
    /// Get value of the field `step`: the update time interval in seconds.
    #[inline(always)]
    pub fn get_step(&self) -> u64 {
        self.step
    }
    /// Get value of the field `digit`: the length of the TOTP code.
    #[inline(always)]
    pub fn get_digit(&self) -> usize {
        self.digit
    }
    /// Get value of the field `t0`: the Unix timestamp of the initial counter time T0.
    #[inline(always)]
    pub fn get_t0(&self) -> u64 {
        self.t0
    }
    /// Get value of the field `hash_algorithm`.
    #[inline(always)]
    pub fn get_hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }
}
/// TOTP code generator
///
/// # Example
/// ```
/// use totp_rfc6238::{HashAlgorithm, TotpGenerator};
/// let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/";
/// // Create a non-standard TOTP code generator: 8-digit, updating every 60
/// // seconds, starting at "Jan 01 1970 00:16:40 UTC", using HMAC-SHA512.
/// let totp_generator = TotpGenerator::new()
///     .set_digit(8).unwrap()
///     .set_step(60).unwrap()
///     .set_t0(1000)
///     .set_hash_algorithm(HashAlgorithm::SHA512)
///     .build();
///
/// let output1 = totp_generator.get_code(key);
/// println!("Your TOTP code for current time is: {}", output1);
///
/// let output2 = totp_generator.get_next_update_time().unwrap();
/// println!("Next update will be at the unix timestamp of {}", output2);
///
/// let output3 = totp_generator.get_code_window(key, -5..=5).unwrap();
/// println!("Codes for 5 minutes earlier or later are:");
/// for i in output3 {
///     println!("  {}", i);
/// }
/// ```
///
/// # Why this struct doesn't store the keys?
/// * The `key` is the **secret credential** of TOTP.
/// * For some reasons, programmers may consider keeping [TotpGenerator]
///   nstances in memory for a period of time.
/// * However, the keys should not be kept in memory for a long time if they do
///   not need to be used during this time. Especially for those devices with a
///   certain secure storage area, storing the keys in the memory for a long time
///   weakens the security system.
/// * Therefore, we recommend: the `key` is only loaded into memory when needed.
///   And, when the operation is done, use some reliable method to overwrite the
///   memory area corresponding to `key`. (For example, the crate
///   [zeroize](https://crates.io/crates/zeroize) might be helpful for this)
/// * The details of security can be very complicated, and we can't include all
///   of them here. If you are interested, you can check the relevant information
///   yourself. If you have better suggestions, please don't hesitate to discuss
///   on [GitHub](https://github.com/KaneGreen/totp_rfc6238) [Issues](https://github.com/KaneGreen/totp_rfc6238/issues)
///   or start a [Pull Request](https://github.com/KaneGreen/totp_rfc6238/pulls).
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct TotpGenerator {
    current: Option<u64>,
    digit: usize,
    step: u64,
    t0: u64,
    hash_algorithm: HashAlgorithm,
}
impl TotpGenerator {
    /// Create a new [builder](./struct.TotpBuilder.html) of TotpGenerator.
    ///
    /// Default value: digit = 6, step = 30, t0 = 0, HashAlgorithm::SHA1.  
    /// These step = 30, t0 = 0 are default values in
    /// [RFC 6238 Section 4](https://tools.ietf.org/html/rfc6238#section-4).
    pub fn new() -> TotpBuilder {
        TotpBuilder::default()
    }
    /// Generate the TOTP code using the given key bytes.
    ///
    /// # Panics
    /// Panics if the current system time is earlier than the Unix epoch
    /// (1970-01-01T00:00:00Z) and this instance of TotpGenerator is using the
    /// system time.
    pub fn get_code(&self, key: &[u8]) -> String {
        self.get_code_with(key, || Self::get_target_time(self.current))
    }
    /// Generate the TOTP code using a closure to specify the time (For example,
    /// getting network time instead of using system time).
    pub fn get_code_with<F: Fn() -> u64>(&self, key: &[u8], func: F) -> String {
        let current = func();
        let count = time_based_counter_bytes(current, self.t0, self.step);
        let mac: Vec<_> = hmac_sha(&count, key, self.hash_algorithm);
        truncate(&mac[..], self.digit)
    }
    /// Generate a window of contiguous TOTP codes (This may be helpful for
    /// time tolerance).  
    /// This returns `None` if the iterator `window` cannot produce a valid
    /// TOTP counter value.
    ///
    /// # Example
    ///
    /// ```
    /// use totp_rfc6238::TotpGenerator;
    /// use std::thread::sleep;
    /// use std::time::Duration;
    /// let shared_key = b"12345678901234567890";
    /// // a fast TOTP that updates every seconds
    /// let client_totp = TotpGenerator::new().set_step(1).unwrap().build();
    /// let client_code = client_totp.get_code(shared_key);
    ///
    /// // Let's simulate the time difference.
    /// sleep(Duration::from_millis(800));
    ///
    /// let server_totp = TotpGenerator::new().set_step(1).unwrap().build();
    /// // This provides time tolerance of -2 ~ +2 period.
    /// let server_code = server_totp.get_code_window(shared_key, -2..=2).unwrap();
    /// assert!(server_code.iter().any(|x| x == client_code.as_str()));
    /// ```
    ///
    /// # Panics
    /// Panics if the current system time is earlier than the Unix epoch
    /// (1970-01-01T00:00:00Z) and this instance of TotpGenerator is using the
    /// system time.
    pub fn get_code_window<T: Iterator<Item = isize>>(
        &self,
        key: &[u8],
        window: T,
    ) -> Option<Vec<String>> {
        self.get_code_window_with(key, window, || Self::get_target_time(self.current))
    }
    /// Generate a window of contiguous TOTP codes using a closure to specify
    /// the time.
    pub fn get_code_window_with<T: Iterator<Item = isize>, F: Fn() -> u64>(
        &self,
        key: &[u8],
        window: T,
        func: F,
    ) -> Option<Vec<String>> {
        let current = func();
        let origin_count = time_based_counter_number(current, self.t0, self.step);
        let mut output = Vec::new();
        for i in window {
            let tmp_count = if i < 0 {
                match origin_count.checked_sub((-i) as u64) {
                    Some(x) => x,
                    None => continue,
                }
            } else {
                match origin_count.checked_add(i as u64) {
                    Some(x) => x,
                    None => continue,
                }
            }
            .to_be_bytes();
            let mac: Vec<_> = hmac_sha(&tmp_count, key, self.hash_algorithm);
            output.push(truncate(&mac[..], self.digit));
        }
        if output.is_empty() {
            None
        } else {
            Some(output)
        }
    }
    /// Get the next timestamp when the TOTP code will be updated.  
    /// This returns `None` if timestamp goes over the maximum of 64-bit
    /// unsigned integer.
    ///
    /// # Panics
    /// Panics if the current system time is earlier than the Unix epoch
    /// (1970-01-01T00:00:00Z) and this instance of TotpGenerator is using the
    /// system time.
    pub fn get_next_update_time(&self) -> Option<u64> {
        let this_time = Self::get_target_time(self.current);
        let this_count = time_based_counter_number(this_time, self.t0, self.step);
        this_count
            .checked_add(1)
            .and_then(|x| x.checked_mul(self.step))
            .and_then(|x| x.checked_add(self.t0))
    }
    /// Store or update a fixed timestamp and make this instance use that time
    /// to generate TOTP codes.  
    /// This method returns the previously stored timestamp.
    ///
    /// # Example
    /// ```
    /// use totp_rfc6238::TotpGenerator;
    /// let mut totp_generator = TotpGenerator::new().set_digit(8).unwrap().build();
    /// let key = b"12345678901234567890";
    ///
    /// assert_eq!(totp_generator.freeze_time(59), None);
    ///
    /// let output1 = totp_generator.get_code(key);
    /// assert_eq!(output1.as_str(), "94287082");
    ///
    /// assert_eq!(totp_generator.release_time(), Some(59));
    ///
    /// let output2 = totp_generator.get_code(key);
    /// assert_ne!(output1.as_str(), output2.as_str());
    /// ```
    pub fn freeze_time(&mut self, timestamp: u64) -> Option<u64> {
        let old = self.current;
        self.current = Some(timestamp);
        old
    }
    /// Remove the stored timestamp. This is the opposite of the
    /// [`TotpGenerator::freeze_time`] method.  
    /// When [`TotpGenerator::get_code`] or [`TotpGenerator::get_code_window`]
    /// are called, the system time at that moment will be used.  
    /// This method returns the previously stored timestamp.
    pub fn release_time(&mut self) -> Option<u64> {
        self.current.take()
    }
    /// Get the previously stored timestamp (but do not remove it).  
    /// This returns `None` if no timestamp is stored.
    #[inline(always)]
    pub fn get_frozen_time(&self) -> Option<u64> {
        self.current
    }
    /// Get value of the field `step`: the update time interval in seconds.
    #[inline(always)]
    pub fn get_step(&self) -> u64 {
        self.step
    }
    /// Get value of the field `digit`: the length of the TOTP code.
    #[inline(always)]
    pub fn get_digit(&self) -> usize {
        self.digit
    }
    /// Get value of the field `t0`: the Unix timestamp of the initial counter time T0.
    #[inline(always)]
    pub fn get_t0(&self) -> u64 {
        self.t0
    }
    /// Get value of the field `hash_algorithm`.
    #[inline(always)]
    pub fn get_hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }
    /// Get the target time of this instance of TotpGenerator.
    ///
    /// # Panics
    /// Panics if the current system time is earlier than the Unix epoch
    /// (1970-01-01T00:00:00Z) and this instance of TotpGenerator is using the
    /// system time.
    #[inline(always)]
    fn get_target_time(time: Option<u64>) -> u64 {
        match time {
            Some(x) => x,
            None => {
                let now_time = SystemTime::now();
                let since_the_epoch = now_time
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                since_the_epoch.as_secs()
            }
        }
    }
}
