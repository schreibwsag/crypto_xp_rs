use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
use crypto_full::api::symmetric::SymKey;

use crypto_full::api::key::KeyManagement;
use crypto_full::api::symmetric::SymmetricCrypto;
use crypto_full::api::hash::HashCrypto;
use crypto_full::api::mac::MacCrypto;
use crypto_full::api::kdf::KdfCrypto;
use crypto_full::api::rng::RngCrypto;
use crypto_full::api::asymmetric::AsymmetricCrypto;
use crypto_full::api::sign::SignatureCrypto;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let p = SoftwareProvider::new();

    // Symmetric: AES-GCM
    let key: SymKey = p.import_symmetric(&[0x11; 32])?;
    let iv_gcm = [0u8; 12];
    let ct = p.encrypt(AES_GCM, &key, &iv_gcm, b"hello world")?;
    let pt = p.decrypt(AES_GCM, &key, &iv_gcm, &ct)?;
    assert_eq!(pt, b"hello world");

    // Hash
    let h = p.hash(SHA2_256, b"abc")?;
    assert_eq!(hex::encode(h), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // HMAC
    let tag = p.mac(HMAC_SHA256, b"key", b"data")?;
    assert!(p.mac_verify(HMAC_SHA256, b"key", b"data", &tag)?);

    // KDF
    let okm = p.derive(HKDF_SHA256, b"ikm", b"info", 32)?;
    assert_eq!(okm.len(), 32);

    // RNG
    let r = p.random(CHACHA20_RNG, 16)?;
    assert_eq!(r.len(), 16);

    // ECDH
    let a = p.generate_keypair(ECDH_P256)?;
    let b = p.generate_keypair(ECDH_P256)?;
    let sa = p.ecdh(ECDH_P256, &a.private, &b.public)?;
    let sb = p.ecdh(ECDH_P256, &b.private, &a.public)?;
    assert_eq!(sa, sb);

    // ECDSA
    let kp = p.generate_keypair(ECDSA_P256)?;
    let sig = p.sign(ECDSA_P256, &kp.private, b"msg")?;
    assert!(p.verify(ECDSA_P256, &kp.public, b"msg", &sig)?);

    Ok(())
}

