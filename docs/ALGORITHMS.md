
# ALGORITHMS

Symmetric
---------
- AES‑CBC (PKCS#7). IV = 16 bytes. **Use AEAD for new designs**.
- AES‑GCM. Nonce = 12 bytes. Provides confidentiality + integrity.
- AES‑CCM (Ccm<Aes256, U16, U13>). Nonce = 13 bytes. Tag = 16 bytes.
- ChaCha20‑Poly1305. Nonce = 12 bytes.

Hashing
-------
- SHA‑2: 256, 512
- SHA‑3: 256, 512

MAC
---
- HMAC: SHA‑256, SHA‑512

KDF
---
- HKDF with SHA‑256/512

Asymmetric
----------
- ECDH P‑256 (shared secret: 32 bytes)
- ECDSA P‑256 (DER signatures)

RNG
---
- ChaCha20Rng seeded from OsRng

