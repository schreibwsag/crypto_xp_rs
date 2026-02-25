use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
use crypto_full::api::symmetric::SymKey;

// Bring trait methods into scope
use crypto_full::api::key::KeyManagement;
use crypto_full::api::symmetric::SymmetricCrypto;
use crypto_full::api::hash::HashCrypto;
use crypto_full::api::mac::MacCrypto;
use crypto_full::api::kdf::KdfCrypto;
use crypto_full::api::rng::RngCrypto;
use crypto_full::api::asymmetric::AsymmetricCrypto;
use crypto_full::api::sign::SignatureCrypto;

fn print_section(title: &str) {
    println!("\n====================================================");
    println!(">>> {}", title);
    println!("====================================================\n");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize provider
    print_section("Initializing Software Crypto Provider");
    let p = SoftwareProvider::new();
    println!("Provider: {}", p.name());

    // AES‑GCM demo
    print_section("AES‑GCM Encryption / Decryption");
    let key: SymKey = p.import_symmetric(&[0x11; 32])?;
    let iv = [0u8; 12];
    let message = b"Hello Crypto Example!";

    println!("Plaintext: {}", String::from_utf8_lossy(message));
    // Do NOT log key bytes. Respect 'no key exposure' policy.
    // If you added SymKey::len(), you can print the size safely:
    // println!("Key: <redacted> (len = {} bytes)", key.len());
    println!("Key: <redacted> (len = 32 bytes)");
    println!("Nonce: {:02x?}", iv);

    let ciphertext = p.encrypt(AES_GCM, &key, &iv, message)?;
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));

    let decrypted = p.decrypt(AES_GCM, &key, &iv, &ciphertext)?;
    println!("Decrypted:  {}", String::from_utf8_lossy(&decrypted));

    // Hashing
    print_section("SHA‑256 Hashing");
    let digest = p.hash(SHA2_256, b"abc")?;
    println!("Input:     \"abc\"");
    println!("SHA2‑256:  {}", hex::encode(digest));

    // HMAC
    print_section("HMAC‑SHA256");
    let tag = p.mac(HMAC_SHA256, b"key", b"data")?;
    println!("Message: \"data\"");
    println!("HMAC tag: {}", hex::encode(&tag));
    println!("Valid:    {}", p.mac_verify(HMAC_SHA256, b"key", b"data", &tag)?);

    // HKDF
    print_section("HKDF (SHA‑256)");
    let okm = p.derive(HKDF_SHA256, b"ikm", b"context-info", 32)?;
    println!("IKM:            \"ikm\"");
    println!("Info:           \"context-info\"");
    println!("Output Key (32): {}", hex::encode(okm));

    // RNG
    print_section("ChaCha20 RNG Example");
    let rnd = p.random(CHACHA20_RNG, 16)?;
    println!("Random bytes (16): {}", hex::encode(rnd));

    // ECDH
    print_section("ECDH (P‑256) – Key Exchange");
    let a = p.generate_keypair(ECDH_P256)?;
    let b = p.generate_keypair(ECDH_P256)?;
    println!("Alice Public (hex): {}", hex::encode(&a.public));
    println!("Bob   Public (hex): {}", hex::encode(&b.public));
    let sa = p.ecdh(ECDH_P256, &a.private, &b.public)?;
    let sb = p.ecdh(ECDH_P256, &b.private, &a.public)?;
    println!("Shared secret A→B: {}", hex::encode(&sa));
    println!("Shared secret B→A: {}", hex::encode(&sb));
    println!("Match: {}", sa == sb);

    // ECDSA
    print_section("ECDSA P‑256 Signature");
    let kp = p.generate_keypair(ECDSA_P256)?;
    let msg = b"sign me please";
    println!("Message: {}", String::from_utf8_lossy(msg));
    let sig = p.sign(ECDSA_P256, &kp.private, msg)?;
    println!("Signature (DER hex): {}", hex::encode(&sig));
    let valid = p.verify(ECDSA_P256, &kp.public, msg, &sig)?;
    println!("Signature valid: {}", valid);

    print_section("DONE ✓");
    Ok(())
}

