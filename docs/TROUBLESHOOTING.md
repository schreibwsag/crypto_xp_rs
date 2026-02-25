
# TROUBLESHOOTING

Build Errors
------------
- **Trait methods not found**: Import the traits (`use crypto_full::api::<domain>::<Trait>;`).
- **CCM type parameters**: Use `Ccm<Aes256, U16, U13>` and pass 13‑byte nonce.
- **CBC padding API**: Use `encrypt_padded_mut` / `decrypt_padded_mut` (cipher 0.4).
- **P‑256 ECDH**: Use `diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine())`.
- **SecretKey::from_be_bytes missing**: Use `from_slice`.
- **Criterion unresolved**: Add `[dev-dependencies] criterion = "0.5"` and bench target.

Runtime Errors
--------------
- **InvalidParam**: Check key sizes and nonce lengths match the algorithm.
- **UnsupportedAlgorithm**: Ensure AlgorithmId is supported by the selected provider.

Logging & Keys
--------------
- Never log keys or secrets. SymKey internals are private on purpose. Provide only safe accessors (e.g., `len()`).

