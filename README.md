Experimental Rust Crypto API for Learning Purposes
==================================================

Build: cargo build
Run example: cargo run --example example_verbose.rs

Test Suite for crypto_full
===============================

This ZIP adds a set of unit tests that exercise the SoftwareProvider through the
provider-agnostic API traits. It assumes A1 (API) and A2 (Software Provider)
are already merged into your project and `Cargo.toml` has the dependencies
from A2.

Usage
-----
Run the tests: cargo test

Notes
-----
- AES-GCM expects 12-byte nonce
- AES-CCM (configured as Ccm<Aes256,U16,U13>) expects 13-byte nonce
- ChaCha20-Poly1305 expects 12-byte nonce
- AES-CBC uses PKCS#7 padding
- ECDSA signatures are DER-encoded
- ECDH shared secret is 32 bytes (raw secret)

Criterion Benchmarks for crypto_full
====================================

Place this folder in your crate root next to src/ and tests/.
Run with:
    cargo bench

