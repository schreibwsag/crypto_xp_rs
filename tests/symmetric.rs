
use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
use crypto_full::api::symmetric::SymKey;
// Bring trait methods into scope
use crypto_full::api::key::KeyManagement;
use crypto_full::api::symmetric::SymmetricCrypto;

#[test]
fn roundtrip_aes_gcm() {
    let p = SoftwareProvider::new();
    let key: SymKey = p.import_symmetric(&[0x11; 32]).unwrap();
    let iv = [0x22; 12];
    let pt = b"hello world";
    let ct = p.encrypt(AES_GCM, &key, &iv, pt).unwrap();
    let dec = p.decrypt(AES_GCM, &key, &iv, &ct).unwrap();
    assert_eq!(pt.to_vec(), dec);
}

#[test]
fn roundtrip_aes_ccm() {
    let p = SoftwareProvider::new();
    let key: SymKey = p.import_symmetric(&[0x42; 32]).unwrap();
    let iv = [0x33; 13]; // CCM 13-byte nonce
    let pt = b"hello world ccm";
    let ct = p.encrypt(AES_CCM, &key, &iv, pt).unwrap();
    let dec = p.decrypt(AES_CCM, &key, &iv, &ct).unwrap();
    assert_eq!(pt.to_vec(), dec);
}

#[test]
fn roundtrip_chacha20poly1305() {
    let p = SoftwareProvider::new();
    let key: SymKey = p.import_symmetric(&[0x55; 32]).unwrap();
    let iv = [0x66; 12];
    let pt = b"hello world chacha";
    let ct = p.encrypt(CHACHA20_POLY1305, &key, &iv, pt).unwrap();
    let dec = p.decrypt(CHACHA20_POLY1305, &key, &iv, &ct).unwrap();
    assert_eq!(pt.to_vec(), dec);
}

#[test]
fn roundtrip_aes_cbc() {
    let p = SoftwareProvider::new();
    let key: SymKey = p.import_symmetric(&[0x77; 32]).unwrap();
    let iv = [0x88; 16];
    let pt = b"hello world cbc pkcs7";
    let ct = p.encrypt(AES_CBC, &key, &iv, pt).unwrap();
    let dec = p.decrypt(AES_CBC, &key, &iv, &ct).unwrap();
    assert_eq!(pt.to_vec(), dec);
}
