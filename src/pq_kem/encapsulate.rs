// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Error, Result};
use crate::pq_kem::keys::{HybridPrivateKey, HybridPublicKey, X25519_PUBLIC_KEY_SIZE};
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Seed, B32};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
const HKDF_SALT: &[u8] = b"SHADOW-VAULT-PQ-KEM-V1-SALT";
const HKDF_INFO_PREFIX: &[u8] = b"svault-x25519-mlkem768-chacha20poly1305";

/// The encapsulated key material returned by the hybrid encapsulation operation.
pub struct EncapsulationResult {
    pub ephemeral_x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
    pub mlkem_ciphertext: [u8; MLKEM768_CIPHERTEXT_SIZE],
    pub shared_key: Zeroizing<[u8; 32]>,
}

/// Encapsulate a shared symmetric secret against a recipient hybrid public key.
pub fn encapsulate_hybrid<R: CryptoRng + RngCore>(
    recipient_pk: &HybridPublicKey,
    rng: &mut R,
) -> Result<EncapsulationResult> {
    // 1. Classical Ephemeral X25519 Key Exchange
    let mut ephemeral_sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_sk_bytes);
    let ephemeral_sk = StaticSecret::from(ephemeral_sk_bytes);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);

    let recipient_x25519 = X25519PublicKey::from(recipient_pk.x25519_pk);
    let ss_classic = ephemeral_sk.diffie_hellman(&recipient_x25519);

    // 2. Post-Quantum ML-KEM-768 Encapsulation
    let mut m_bytes = [0u8; 32];
    rng.fill_bytes(&mut m_bytes);
    let m: B32 = m_bytes.into();

    let ek = EncapsulationKey768::new(&recipient_pk.mlkem_ek.into())
        .map_err(|_| Error::Kem("failed to deserialize recipient ML-KEM public key".into()))?;

    let (ct, ss_pq) = ek.encapsulate_deterministic(&m);
    let mut mlkem_ciphertext = [0u8; MLKEM768_CIPHERTEXT_SIZE];
    mlkem_ciphertext.copy_from_slice(&ct);

    // 3. Dual-Layer Hybrid Key Derivation via HKDF-SHA256
    let shared_key = derive_hybrid_key(
        ss_classic.as_bytes(),
        ss_pq.as_slice(),
        ephemeral_pk.as_bytes(),
        &recipient_pk.x25519_pk,
    );

    Ok(EncapsulationResult {
        ephemeral_x25519_pk: *ephemeral_pk.as_bytes(),
        mlkem_ciphertext,
        shared_key,
    })
}

/// Decapsulate a shared symmetric secret using the recipient hybrid private key.
pub fn decapsulate_hybrid(
    recipient_sk: &HybridPrivateKey,
    ephemeral_x25519_pk: &[u8; X25519_PUBLIC_KEY_SIZE],
    mlkem_ciphertext: &[u8; MLKEM768_CIPHERTEXT_SIZE],
) -> Result<Zeroizing<[u8; 32]>> {
    // 1. Classical X25519 Diffie-Hellman Decapsulation
    let sk = StaticSecret::from(recipient_sk.x25519_sk);
    let peer_pk = X25519PublicKey::from(*ephemeral_x25519_pk);
    let ss_classic = sk.diffie_hellman(&peer_pk);

    // 2. Post-Quantum ML-KEM-768 Decapsulation
    let seed: Seed = recipient_sk.mlkem_seed.into();
    let dk = DecapsulationKey768::from_seed(seed);

    let ct = (*mlkem_ciphertext).into();
    let ss_pq = dk.decapsulate(&ct);

    // 3. Compute recipient X25519 public key for KDF domain separation
    let recipient_pk: X25519PublicKey = (&sk).into();

    // 4. Dual-Layer Hybrid Key Derivation via HKDF-SHA256
    let shared_key = derive_hybrid_key(
        ss_classic.as_bytes(),
        ss_pq.as_slice(),
        ephemeral_x25519_pk,
        recipient_pk.as_bytes(),
    );

    Ok(shared_key)
}

/// Derive a 32-byte authenticated vault key from both classical and post-quantum shared secrets.
fn derive_hybrid_key(
    ss_classic: &[u8; 32],
    ss_pq: &[u8],
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    // HKDF-Extract: PRK = HMAC-SHA256(Salt, IKM = ss_classic || ss_pq)
    let mut hmac_extract = Sha256::new();
    let mut k_opad = [0x5cu8; 64];
    let mut k_ipad = [0x36u8; 64];
    for (i, &b) in HKDF_SALT.iter().enumerate().take(64) {
        k_opad[i] ^= b;
        k_ipad[i] ^= b;
    }

    // Inner hash: H(k_ipad || IKM)
    hmac_extract.update(k_ipad);
    hmac_extract.update(ss_classic);
    hmac_extract.update(ss_pq);
    let inner_hash = hmac_extract.finalize();

    // Outer hash: H(k_opad || inner_hash)
    let mut outer = Sha256::new();
    outer.update(k_opad);
    outer.update(inner_hash);
    let prk = outer.finalize();

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let mut prk_opad = [0x5cu8; 64];
    let mut prk_ipad = [0x36u8; 64];
    for (i, &b) in prk.iter().enumerate().take(32) {
        prk_opad[i] ^= b;
        prk_ipad[i] ^= b;
    }

    let mut expand_inner = Sha256::new();
    expand_inner.update(prk_ipad);
    expand_inner.update(HKDF_INFO_PREFIX);
    expand_inner.update(ephemeral_pk);
    expand_inner.update(recipient_pk);
    expand_inner.update([0x01u8]);
    let expand_inner_hash = expand_inner.finalize();

    let mut expand_outer = Sha256::new();
    expand_outer.update(prk_opad);
    expand_outer.update(expand_inner_hash);
    let okm = expand_outer.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Zeroizing::new(key)
}
