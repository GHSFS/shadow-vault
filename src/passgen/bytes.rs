// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Raw cryptographic random bytes generator.
//!
//! Generates cryptographically strong random byte sequences with support
//! for hexadecimal, standard Base64, and RFC 4648 Base32 encodings.

use base64::prelude::*;
use rand::Rng;
use zeroize::Zeroize;

/// Output encoding formats for raw cryptographic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteEncoding {
    /// Lowercase hexadecimal string (2 chars per byte).
    Hex,
    /// Standard RFC 4648 Base64 with padding.
    Base64,
    /// RFC 4648 Base32 with '=' padding (compatible with TOTP seeds).
    Base32,
}

/// Generate raw CSPRNG random bytes and format according to selected encoding.
///
/// Returns `(encoded_string, theoretical_keyspace_entropy_bits)`.
pub fn generate_random_bytes<R: Rng>(
    rng: &mut R,
    byte_count: usize,
    encoding: ByteEncoding,
) -> (String, f64) {
    let count = byte_count.max(1);
    let mut raw_bytes = vec![0u8; count];
    rng.fill(&mut raw_bytes[..]);

    let entropy_bits = count as f64 * 8.0;

    let encoded = match encoding {
        ByteEncoding::Hex => raw_bytes.iter().map(|b| format!("{b:02x}")).collect(),
        ByteEncoding::Base64 => BASE64_STANDARD.encode(&raw_bytes),
        ByteEncoding::Base32 => crate::totp::base32_encode(&raw_bytes),
    };

    raw_bytes.zeroize();

    (encoded, entropy_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_generate_random_bytes_hex() {
        let mut rng = StdRng::seed_from_u64(5005);
        let (hex_str, entropy) = generate_random_bytes(&mut rng, 32, ByteEncoding::Hex);

        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(entropy, 256.0);
    }

    #[test]
    fn test_generate_random_bytes_base64() {
        let mut rng = StdRng::seed_from_u64(6006);
        let (b64_str, entropy) = generate_random_bytes(&mut rng, 32, ByteEncoding::Base64);

        assert_eq!(entropy, 256.0);
        let decoded = BASE64_STANDARD.decode(&b64_str).expect("invalid base64");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_generate_random_bytes_base32() {
        let mut rng = StdRng::seed_from_u64(7007);
        let (b32_str, entropy) = generate_random_bytes(&mut rng, 20, ByteEncoding::Base32);

        assert_eq!(entropy, 160.0);
        let decoded = crate::totp::base32_decode(&b32_str).expect("invalid base32");
        assert_eq!(decoded.len(), 20);
    }
}
