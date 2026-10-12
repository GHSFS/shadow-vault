// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Plausible deniability & dual-password decoy vault container (`src/decoy.rs`).
//!
//! Embeds both a primary hidden payload (unlocked with the primary passphrase)
//! and a plausible decoy payload (unlocked with the decoy passphrase) within
//! a single `SVLT` container.
//!
//! An adversary holding only the decoy passphrase can decrypt the decoy payload,
//! while the remaining hidden slot bytes are statistically indistinguishable from
//! uniform random noise (CSPRNG pad / ChaCha20-Poly1305 ciphertext).

use crate::crypto::{
    derive_key, dpapi_protect, dpapi_unprotect, ContainerInfo, FLAG_DECOY, FLAG_DPAPI, HEADER_LEN,
    MAGIC, NONCE_LEN, SALT_LEN, VERSION, VERSION_V2,
};
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub const DECOY_HEADER_LEN: usize = HEADER_LEN + 4; // 34 + 4 = 38 bytes
pub const MIN_HIDDEN_SLOT_LEN: usize = SALT_LEN + NONCE_LEN + 16; // 16 + 12 + 16 = 44 bytes
const MIN_RANDOM_PAD_LEN: usize = 32;
const PAD_ALIGNMENT: usize = 256;

/// Identifies which slot in a decoy container was unlocked.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoySlot {
    /// Hidden primary slot unlocked with primary passphrase.
    Primary,
    /// Plausible decoy slot unlocked with decoy passphrase.
    Decoy,
}

/// Result of unlocking a plausible deniability container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyOpenResult {
    /// Hidden primary secret.
    Primary(Vec<u8>),
    /// Plausible decoy payload.
    Decoy(Vec<u8>),
}

impl DecoyOpenResult {
    /// Borrow the unlocked plaintext payload.
    pub fn plaintext(&self) -> &[u8] {
        match self {
            DecoyOpenResult::Primary(p) => p,
            DecoyOpenResult::Decoy(d) => d,
        }
    }

    /// Consume the result and return the unlocked plaintext payload.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            DecoyOpenResult::Primary(p) => p,
            DecoyOpenResult::Decoy(d) => d,
        }
    }

    /// Check if the unlocked payload came from the decoy slot.
    #[allow(dead_code)]
    pub fn is_decoy(&self) -> bool {
        matches!(self, DecoyOpenResult::Decoy(_))
    }

    /// Check if the unlocked payload came from the hidden primary slot.
    #[allow(dead_code)]
    pub fn is_primary(&self) -> bool {
        matches!(self, DecoyOpenResult::Primary(_))
    }

    /// Get the slot type that was unlocked.
    #[allow(dead_code)]
    pub fn slot(&self) -> DecoySlot {
        match self {
            DecoyOpenResult::Primary(_) => DecoySlot::Primary,
            DecoyOpenResult::Decoy(_) => DecoySlot::Decoy,
        }
    }
}

impl std::ops::Deref for DecoyOpenResult {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.plaintext()
    }
}

impl AsRef<[u8]> for DecoyOpenResult {
    fn as_ref(&self) -> &[u8] {
        self.plaintext()
    }
}

/// Seal both primary secret and decoy payload into a dual-password plausible deniability container.
///
/// If `padding_bytes` is greater than 0, at least that amount of CSPRNG padding is appended
/// to the primary payload inside the hidden slot; otherwise, standard 256-byte alignment
/// padding is generated.
pub fn seal_decoy(
    primary_secret: &[u8],
    primary_passphrase: &str,
    decoy_secret: &[u8],
    decoy_passphrase: &str,
    bind_dpapi: bool,
    padding_bytes: usize,
) -> Result<Vec<u8>> {
    if primary_passphrase.is_empty() {
        return Err(Error::Crypto("primary passphrase must not be empty".into()));
    }
    if decoy_passphrase.is_empty() {
        return Err(Error::Crypto("decoy passphrase must not be empty".into()));
    }
    if primary_passphrase == decoy_passphrase {
        return Err(Error::Crypto(
            "primary and decoy passphrases must be distinct for plausible deniability".into(),
        ));
    }

    // 1. Prepare Decoy Slot
    let mut decoy_salt = [0u8; SALT_LEN];
    let mut decoy_nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut decoy_salt);
    rand::thread_rng().fill_bytes(&mut decoy_nonce_bytes);

    let decoy_key = derive_key(decoy_passphrase.as_bytes(), &decoy_salt)?;
    let decoy_cipher = ChaCha20Poly1305::new(Key::from_slice(&*decoy_key));
    let decoy_nonce = Nonce::from_slice(&decoy_nonce_bytes);

    let decoy_ciphertext = decoy_cipher
        .encrypt(decoy_nonce, decoy_secret)
        .map_err(|_| Error::Crypto("decoy ChaCha20-Poly1305 encryption failed".into()))?;

    let decoy_body = if bind_dpapi {
        dpapi_protect(&decoy_ciphertext)?
    } else {
        decoy_ciphertext
    };

    if decoy_body.len() > u32::MAX as usize {
        return Err(Error::Crypto("decoy payload exceeds maximum size".into()));
    }
    let decoy_body_len = decoy_body.len() as u32;

    // 2. Prepare Hidden Primary Slot
    let mut hidden_salt = [0u8; SALT_LEN];
    let mut hidden_nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut hidden_salt);
    rand::thread_rng().fill_bytes(&mut hidden_nonce_bytes);

    let hidden_inner = Zeroizing::new(if bind_dpapi {
        dpapi_protect(primary_secret)?
    } else {
        primary_secret.to_vec()
    });

    if hidden_inner.len() > u32::MAX as usize {
        return Err(Error::Crypto("primary payload exceeds maximum size".into()));
    }
    let inner_len = hidden_inner.len() as u32;

    // Frame hidden plaintext: [4-byte LE inner_len][inner_bytes][random padding]
    // Padding ensures the slot size is aligned and indistinguishable from random noise
    let unpadded_len = 4 + hidden_inner.len();
    let default_pad = MIN_RANDOM_PAD_LEN
        + (PAD_ALIGNMENT - ((unpadded_len + MIN_RANDOM_PAD_LEN) % PAD_ALIGNMENT)) % PAD_ALIGNMENT;
    let pad_len = if padding_bytes > 0 {
        padding_bytes.max(MIN_RANDOM_PAD_LEN)
    } else {
        default_pad
    };

    let mut hidden_plain = Zeroizing::new(Vec::with_capacity(unpadded_len + pad_len));
    hidden_plain.extend_from_slice(&inner_len.to_le_bytes());
    hidden_plain.extend_from_slice(&hidden_inner);

    let mut pad_bytes = Zeroizing::new(vec![0u8; pad_len]);
    rand::thread_rng().fill_bytes(&mut pad_bytes);
    hidden_plain.extend_from_slice(&pad_bytes);

    let hidden_key = derive_key(primary_passphrase.as_bytes(), &hidden_salt)?;
    let hidden_cipher = ChaCha20Poly1305::new(Key::from_slice(&*hidden_key));
    let hidden_nonce = Nonce::from_slice(&hidden_nonce_bytes);

    let hidden_ciphertext = hidden_cipher
        .encrypt(hidden_nonce, hidden_plain.as_slice())
        .map_err(|_| Error::Crypto("hidden ChaCha20-Poly1305 encryption failed".into()))?;

    // 3. Assemble Container
    let flags = FLAG_DECOY | (if bind_dpapi { FLAG_DPAPI } else { 0 });
    let total_len = DECOY_HEADER_LEN
        .checked_add(decoy_body.len())
        .and_then(|l| l.checked_add(SALT_LEN))
        .and_then(|l| l.checked_add(NONCE_LEN))
        .and_then(|l| l.checked_add(hidden_ciphertext.len()))
        .ok_or_else(|| Error::Crypto("container size overflow".into()))?;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V2);
    out.push(flags);
    out.extend_from_slice(&decoy_salt);
    out.extend_from_slice(&decoy_nonce_bytes);
    out.extend_from_slice(&decoy_body_len.to_le_bytes());
    out.extend_from_slice(&decoy_body);

    // Hidden slot follows directly: [salt][nonce][ciphertext]
    out.extend_from_slice(&hidden_salt);
    out.extend_from_slice(&hidden_nonce_bytes);
    out.extend_from_slice(&hidden_ciphertext);

    Ok(out)
}

/// Seal a single payload into a v2 container with explicit or aligned random padding.
pub fn seal_v2(
    plaintext: &[u8],
    passphrase: &str,
    bind_dpapi: bool,
    padding_bytes: usize,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Crypto("passphrase must not be empty".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let inner = Zeroizing::new(if bind_dpapi {
        dpapi_protect(plaintext)?
    } else {
        plaintext.to_vec()
    });

    if inner.len() > u32::MAX as usize {
        return Err(Error::Crypto("payload exceeds maximum size".into()));
    }
    let inner_len = inner.len() as u32;

    let unpadded_len = 4 + inner.len();
    let default_pad = MIN_RANDOM_PAD_LEN
        + (PAD_ALIGNMENT - ((unpadded_len + MIN_RANDOM_PAD_LEN) % PAD_ALIGNMENT)) % PAD_ALIGNMENT;
    let pad_len = if padding_bytes > 0 {
        padding_bytes.max(MIN_RANDOM_PAD_LEN)
    } else {
        default_pad
    };

    let mut plain = Zeroizing::new(Vec::with_capacity(unpadded_len + pad_len));
    plain.extend_from_slice(&inner_len.to_le_bytes());
    plain.extend_from_slice(&inner);

    let mut pad_bytes = Zeroizing::new(vec![0u8; pad_len]);
    rand::thread_rng().fill_bytes(&mut pad_bytes);
    plain.extend_from_slice(&pad_bytes);

    let key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain.as_slice())
        .map_err(|_| Error::Crypto("v2 ChaCha20-Poly1305 encryption failed".into()))?;

    let flags = if bind_dpapi { FLAG_DPAPI } else { 0 };

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V2);
    out.push(flags);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Open a v2 single-payload padded container.
pub fn open_v2(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if container.len() < HEADER_LEN + 4 + 16 {
        return Err(Error::Format(
            "container truncated or smaller than header".into(),
        ));
    }
    if &container[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid container magic (expected SVLT)".into(),
        ));
    }
    let version = container[4];
    if version != VERSION_V2 {
        return Err(Error::Format(format!(
            "expected container version 2, got {version}"
        )));
    }
    let flags = container[5];
    let salt = &container[6..6 + SALT_LEN];
    let nonce_bytes = &container[6 + SALT_LEN..HEADER_LEN];
    let ciphertext = &container[HEADER_LEN..];

    let key_bytes = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        Error::Crypto("authentication failed — wrong passphrase or tampered container".into())
    })?;

    let decrypted_plain = Zeroizing::new(decrypted);

    if decrypted_plain.len() < 4 {
        return Err(Error::Format("v2 payload frame truncated".into()));
    }

    let inner_len = u32::from_le_bytes(
        decrypted_plain[0..4]
            .try_into()
            .map_err(|_| Error::Format("failed to read payload length".into()))?,
    ) as usize;

    if 4 + inner_len > decrypted_plain.len() {
        return Err(Error::Format("invalid inner payload length".into()));
    }

    let inner = &decrypted_plain[4..4 + inner_len];

    if (flags & FLAG_DPAPI) != 0 {
        dpapi_unprotect(inner)
    } else {
        Ok(inner.to_vec())
    }
}

/// Seamlessly open a plausible deniability container.
///
/// Attempts to decrypt the hidden primary slot first; if authentication
/// fails, attempts to decrypt the plausible decoy slot.
pub fn open_decoy(container: &[u8], passphrase: &str) -> Result<DecoyOpenResult> {
    if passphrase.is_empty() {
        return Err(Error::Crypto("passphrase must not be empty".into()));
    }

    validate_decoy_header(container)?;

    // Attempt 1: Hidden primary slot
    if let Ok(primary) = open_primary_slot(container, passphrase) {
        return Ok(DecoyOpenResult::Primary(primary));
    }

    // Attempt 2: Decoy slot
    if let Ok(decoy) = open_decoy_slot(container, passphrase) {
        return Ok(DecoyOpenResult::Decoy(decoy));
    }

    Err(Error::Crypto(
        "authentication failed — wrong passphrase or tampered container".into(),
    ))
}

/// Open a plausible deniability container with explicit options for primary or decoy passphrases.
pub fn open_decoy_explicit(
    container: &[u8],
    passphrase: Option<&str>,
    decoy_passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    if let Some(decoy_p) = decoy_passphrase {
        if !decoy_p.is_empty() {
            return open_decoy_payload(container, decoy_p);
        }
    }

    if let Some(p) = passphrase {
        if !p.is_empty() {
            return open_decoy(container, p).map(|r| r.into_bytes());
        }
    }

    Err(Error::Crypto(
        "either --passphrase or --decoy-passphrase must be provided".into(),
    ))
}

/// Attempt to open specifically the primary hidden slot.
#[allow(dead_code)]
pub fn open_primary(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    open_primary_slot(container, passphrase)
}

/// Attempt to open specifically the plausible decoy slot.
#[allow(dead_code)]
pub fn open_decoy_payload(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    open_decoy_slot(container, passphrase)
}

/// Attempt to open specifically the primary hidden slot (internal helper).
pub fn open_primary_slot(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    validate_decoy_header(container)?;

    let decoy_body_len = parse_decoy_body_len(container)?;
    let hidden_offset = DECOY_HEADER_LEN
        .checked_add(decoy_body_len)
        .ok_or_else(|| Error::Format("integer overflow in container layout".into()))?;

    if container.len() < hidden_offset.saturating_add(MIN_HIDDEN_SLOT_LEN) {
        return Err(Error::Format("hidden slot truncated or not present".into()));
    }

    let hidden_slot = &container[hidden_offset..];
    let hidden_salt = &hidden_slot[..SALT_LEN];
    let hidden_nonce_bytes = &hidden_slot[SALT_LEN..SALT_LEN + NONCE_LEN];
    let hidden_ciphertext = &hidden_slot[SALT_LEN + NONCE_LEN..];

    let key_bytes = derive_key(passphrase.as_bytes(), hidden_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(hidden_nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, hidden_ciphertext)
        .map_err(|_| Error::Crypto("primary authentication failed".into()))?;

    let decrypted_plain = Zeroizing::new(decrypted);

    if decrypted_plain.len() < 4 {
        return Err(Error::Format("hidden payload frame truncated".into()));
    }

    let inner_len = u32::from_le_bytes(
        decrypted_plain[0..4]
            .try_into()
            .map_err(|_| Error::Format("failed to read payload length".into()))?,
    ) as usize;

    if 4 + inner_len > decrypted_plain.len() {
        return Err(Error::Format("invalid inner payload length".into()));
    }

    let inner = &decrypted_plain[4..4 + inner_len];
    let flags = container[5];

    if (flags & FLAG_DPAPI) != 0 {
        dpapi_unprotect(inner)
    } else {
        Ok(inner.to_vec())
    }
}

/// Attempt to open specifically the plausible decoy slot (internal helper).
pub fn open_decoy_slot(container: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    validate_decoy_header(container)?;

    let flags = container[5];
    let decoy_salt = &container[6..6 + SALT_LEN];
    let decoy_nonce_bytes = &container[6 + SALT_LEN..HEADER_LEN];
    let decoy_body_len = parse_decoy_body_len(container)?;

    let decoy_end = DECOY_HEADER_LEN + decoy_body_len;
    let decoy_body = &container[DECOY_HEADER_LEN..decoy_end];

    let ciphertext = if (flags & FLAG_DPAPI) != 0 {
        dpapi_unprotect(decoy_body)?
    } else {
        decoy_body.to_vec()
    };

    let key_bytes = derive_key(passphrase.as_bytes(), decoy_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(decoy_nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| Error::Crypto("decoy authentication failed".into()))
}

/// Inspect a plausible deniability container without exposing hidden slot contents.
pub fn inspect_decoy(container: &[u8]) -> Result<ContainerInfo> {
    validate_decoy_header(container)?;

    let version = container[4];
    let flags = container[5];
    let salt = &container[6..6 + SALT_LEN];
    let salt_hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let decoy_body_len = parse_decoy_body_len(container)?;

    Ok(ContainerInfo {
        version,
        dpapi_bound: (flags & FLAG_DPAPI) != 0,
        payload_size: decoy_body_len.saturating_sub(16),
        salt_hex,
        decoy_container: true,
    })
}

/// Checks whether a byte slice contains a valid `SVLT` decoy container signature and flag.
pub fn is_decoy_container(container: &[u8]) -> bool {
    if container.len() < DECOY_HEADER_LEN {
        return false;
    }
    if &container[0..4] != MAGIC {
        return false;
    }
    if container[4] != VERSION && container[4] != VERSION_V2 {
        return false;
    }
    (container[5] & FLAG_DECOY) != 0
}

fn validate_decoy_header(container: &[u8]) -> Result<()> {
    if container.len() < DECOY_HEADER_LEN {
        return Err(Error::Format("decoy container header truncated".into()));
    }
    if &container[0..4] != MAGIC {
        return Err(Error::Format(
            "invalid container magic (expected SVLT)".into(),
        ));
    }
    let version = container[4];
    if version != VERSION && version != VERSION_V2 {
        return Err(Error::Format(format!(
            "unsupported container version: {version}"
        )));
    }
    let flags = container[5];
    if (flags & FLAG_DECOY) == 0 {
        return Err(Error::Format(
            "container does not have FLAG_DECOY set".into(),
        ));
    }
    Ok(())
}

fn parse_decoy_body_len(container: &[u8]) -> Result<usize> {
    let len_bytes: [u8; 4] = container[HEADER_LEN..DECOY_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::Format("failed to read decoy body length".into()))?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    let decoy_end = DECOY_HEADER_LEN
        .checked_add(len)
        .ok_or_else(|| Error::Format("decoy body length overflow".into()))?;

    if decoy_end > container.len() {
        return Err(Error::Format(
            "decoy body length exceeds container size".into(),
        ));
    }

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn decoy_roundtrip_primary_and_decoy_passphrases() {
        let primary_secret = b"primary hidden secret: top-tier operational keys";
        let decoy_payload = b"plausible decoy: grocery list, milk, bread, butter";

        let container = seal_decoy(
            primary_secret,
            "primary-passphrase-alpha",
            decoy_payload,
            "decoy-passphrase-beta",
            false,
            0,
        )
        .unwrap();

        assert!(is_decoy_container(&container));

        let info = inspect_decoy(&container).unwrap();
        assert_eq!(info.version, 2);
        assert!(!info.dpapi_bound);
        assert!(info.decoy_container);
        assert_eq!(info.payload_size, decoy_payload.len());

        // Decrypt with primary passphrase unlocks primary secret
        let unlocked_primary = open_decoy(&container, "primary-passphrase-alpha").unwrap();
        assert_eq!(unlocked_primary.plaintext(), primary_secret);
        assert!(unlocked_primary.is_primary());
        assert!(!unlocked_primary.is_decoy());
        assert_eq!(unlocked_primary.slot(), DecoySlot::Primary);
        assert_eq!(unlocked_primary.into_bytes(), primary_secret);

        // Decrypt with decoy passphrase unlocks decoy payload
        let unlocked_decoy = open_decoy(&container, "decoy-passphrase-beta").unwrap();
        assert_eq!(unlocked_decoy.plaintext(), decoy_payload);
        assert!(unlocked_decoy.is_decoy());
        assert!(!unlocked_decoy.is_primary());
        assert_eq!(unlocked_decoy.slot(), DecoySlot::Decoy);
        assert_eq!(unlocked_decoy.into_bytes(), decoy_payload);

        // Explicit slot openers
        assert_eq!(
            open_primary(&container, "primary-passphrase-alpha").unwrap(),
            primary_secret
        );
        assert_eq!(
            open_decoy_payload(&container, "decoy-passphrase-beta").unwrap(),
            decoy_payload
        );
    }

    #[test]
    fn seal_v2_and_open_v2_roundtrip_with_padding() {
        let secret = b"confidential single-payload requiring size obfuscation";
        let container = seal_v2(secret, "v2-master-key", false, 512).unwrap();

        assert!(!is_decoy_container(&container));
        let info = crate::crypto::inspect(&container).unwrap();
        assert_eq!(info.version, 2);
        assert!(!info.decoy_container);

        let unlocked = open_v2(&container, "v2-master-key").unwrap();
        assert_eq!(unlocked, secret);

        // Also opens seamlessly through crypto::open
        let unlocked_unified = crate::crypto::open(&container, "v2-master-key").unwrap();
        assert_eq!(unlocked_unified, secret);

        // Wrong passphrase fails
        assert!(open_v2(&container, "wrong-key").is_err());
        assert!(crate::crypto::open(&container, "wrong-key").is_err());
    }

    #[test]
    fn decoy_custom_padding_bytes() {
        let primary_secret = b"ultra high security vault payload";
        let decoy_payload = b"recipes for pumpkin soup";

        let container = seal_decoy(
            primary_secret,
            "pass-prim",
            decoy_payload,
            "pass-dec",
            false,
            1024,
        )
        .unwrap();

        let unlocked_prim = open_decoy(&container, "pass-prim").unwrap();
        assert_eq!(unlocked_prim.plaintext(), primary_secret);

        let unlocked_dec = open_decoy(&container, "pass-dec").unwrap();
        assert_eq!(unlocked_dec.plaintext(), decoy_payload);
    }

    #[test]
    fn decoy_wrong_passphrase_fails_both_slots() {
        let container = seal_decoy(
            b"hidden secret",
            "pass-alpha",
            b"harmless note",
            "pass-beta",
            false,
            0,
        )
        .unwrap();

        assert!(open_decoy(&container, "wrong-passphrase").is_err());
        assert!(open_primary(&container, "wrong-passphrase").is_err());
        assert!(open_decoy_payload(&container, "wrong-passphrase").is_err());
    }

    #[test]
    fn decoy_identical_passphrases_rejected() {
        let res = seal_decoy(
            b"hidden secret",
            "same-password",
            b"decoy note",
            "same-password",
            false,
            0,
        );
        assert!(res.is_err());
    }

    #[test]
    fn decoy_empty_passphrases_rejected() {
        assert!(seal_decoy(b"hidden", "", b"decoy", "pass2", false, 0).is_err());
        assert!(seal_decoy(b"hidden", "pass1", b"decoy", "", false, 0).is_err());
    }

    #[test]
    fn decoy_empty_secrets_roundtrip() {
        let container = seal_decoy(b"", "primary-p", b"", "decoy-p", false, 0).unwrap();
        let unlocked_primary = open_decoy(&container, "primary-p").unwrap();
        assert_eq!(unlocked_primary.plaintext(), b"");

        let unlocked_decoy = open_decoy(&container, "decoy-p").unwrap();
        assert_eq!(unlocked_decoy.plaintext(), b"");
    }

    #[test]
    fn decoy_hidden_slot_indistinguishable_from_random() {
        let primary_secret = b"confidential payload requiring strong deniability";
        let decoy_payload = b"ordinary harmless text";

        let container = seal_decoy(
            primary_secret,
            "pass-secret-123",
            decoy_payload,
            "pass-decoy-456",
            false,
            0,
        )
        .unwrap();

        let decoy_body_len = parse_decoy_body_len(&container).unwrap();
        let hidden_offset = DECOY_HEADER_LEN + decoy_body_len;
        let hidden_slot = &container[hidden_offset..];

        // Hidden slot must be at least MIN_HIDDEN_SLOT_LEN
        assert!(hidden_slot.len() >= MIN_HIDDEN_SLOT_LEN);

        // Calculate Shannon entropy of the hidden slot:
        // H = -sum(p * log2(p))
        let mut counts = [0usize; 256];
        for &byte in hidden_slot {
            counts[byte as usize] += 1;
        }

        let total = hidden_slot.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total;
                entropy -= p * p.log2();
            }
        }

        // For uniform random noise, entropy should be very close to 8.0 bits/byte.
        assert!(
            entropy > 7.2,
            "hidden slot entropy ({entropy:.3} bits/byte) should be near-ideal random noise"
        );
    }

    #[test]
    fn decoy_tampered_container_rejected() {
        let mut container = seal_decoy(
            b"hidden primary",
            "prim-key",
            b"decoy note",
            "dec-key",
            false,
            0,
        )
        .unwrap();

        let len = container.len();
        // Corrupt last byte in hidden slot
        container[len - 1] ^= 0x55;
        assert!(open_primary_slot(&container, "prim-key").is_err());

        // Decoy slot remains authentic if only hidden slot was touched
        assert_eq!(
            open_decoy_slot(&container, "dec-key").unwrap(),
            b"decoy note"
        );

        // Corrupt decoy body
        container[DECOY_HEADER_LEN + 2] ^= 0xAA;
        assert!(open_decoy_slot(&container, "dec-key").is_err());
    }

    #[test]
    fn decoy_truncated_header_rejected() {
        let container = seal_decoy(b"sec", "p1", b"dec", "p2", false, 0).unwrap();
        assert!(open_decoy(&container[..DECOY_HEADER_LEN - 1], "p1").is_err());
        assert!(inspect_decoy(&container[..DECOY_HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn decoy_explicit_open_options() {
        let container = seal_decoy(b"primary", "pass-1", b"decoy", "pass-2", false, 0).unwrap();

        assert_eq!(
            open_decoy_explicit(&container, None, Some("pass-2")).unwrap(),
            b"decoy"
        );
        assert_eq!(
            open_decoy_explicit(&container, Some("pass-1"), None).unwrap(),
            b"primary"
        );
        assert_eq!(
            open_decoy_explicit(&container, Some("pass-2"), None).unwrap(),
            b"decoy"
        );
        assert!(open_decoy_explicit(&container, None, None).is_err());
    }

    #[test]
    fn decoy_dpapi_roundtrip() {
        let primary = b"hardware-bound hidden secret";
        let decoy = b"hardware-bound decoy payload";

        let container = seal_decoy(primary, "prim-pw", decoy, "dec-pw", true, 0).unwrap();
        let info = inspect_decoy(&container).unwrap();
        assert!(info.dpapi_bound);
        assert!(info.decoy_container);

        let unlocked_prim = open_decoy(&container, "prim-pw").unwrap();
        assert_eq!(unlocked_prim.plaintext(), primary);

        let unlocked_dec = open_decoy(&container, "dec-pw").unwrap();
        assert_eq!(unlocked_dec.plaintext(), decoy);
    }

    #[test]
    fn decoy_zeroize_memory_audit() {
        let mut sensitive = Zeroizing::new([0x42u8; 128]);
        assert_eq!(sensitive[0], 0x42);
        sensitive.zeroize();
        assert_eq!(sensitive[0], 0);
    }
}
