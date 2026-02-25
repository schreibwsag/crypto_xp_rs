
use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
// Bring trait methods into scope
use crypto_full::api::asymmetric::AsymmetricCrypto;
use crypto_full::api::sign::SignatureCrypto;

#[test]
fn ecdh_and_ecdsa() {
    let p = SoftwareProvider::new();

    // ECDH shared secret equality
    let a = p.generate_keypair(ECDH_P256).unwrap();
    let b = p.generate_keypair(ECDH_P256).unwrap();
    let sa = p.ecdh(ECDH_P256, &a.private, &b.public).unwrap();
    let sb = p.ecdh(ECDH_P256, &b.private, &a.public).unwrap();
    assert_eq!(sa, sb);

    // ECDSA sign/verify
    let kp = p.generate_keypair(ECDSA_P256).unwrap();
    let msg = b"sign me";
    let sig = p.sign(ECDSA_P256, &kp.private, msg).unwrap();
    assert!(p.verify(ECDSA_P256, &kp.public, msg, &sig).unwrap());
}
