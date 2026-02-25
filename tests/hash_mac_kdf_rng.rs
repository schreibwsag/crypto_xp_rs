
use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
// Bring trait methods into scope
use crypto_full::api::hash::HashCrypto;
use crypto_full::api::mac::MacCrypto;
use crypto_full::api::kdf::KdfCrypto;
use crypto_full::api::rng::RngCrypto;

#[test]
fn hash_and_mac_and_kdf_and_rng() {
    let p = SoftwareProvider::new();

    // Hash
    let h = p.hash(SHA2_256, b"abc").unwrap();
    assert_eq!(hex::encode(h), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // MAC
    let tag = p.mac(HMAC_SHA256, b"key", b"data").unwrap();
    assert!(p.mac_verify(HMAC_SHA256, b"key", b"data", &tag).unwrap());

    // KDF
    let okm = p.derive(HKDF_SHA256, b"ikm", b"info", 32).unwrap();
    assert_eq!(okm.len(), 32);

    // RNG
    let rnd = p.random(CHACHA20_RNG, 64).unwrap();
    assert_eq!(rnd.len(), 64);
}
