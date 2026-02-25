
# ARCHITECTURE

This component separates a provider‑agnostic **API** (traits + AlgorithmId) from **providers**.

```
api/                  # Traits & AlgorithmId
  provider.rs         # AlgorithmId + CryptoProvider
  symmetric.rs        # SymmetricCrypto
  hash.rs             # HashCrypto
  kdf.rs              # KdfCrypto
  rng.rs              # RngCrypto
  mac.rs              # MacCrypto
  sign.rs             # SignatureCrypto
  asymmetric.rs       # AsymmetricCrypto
  key.rs              # KeyManagement

providers/
  software/           # Full software provider implementation
    symmetric_sw.rs
    hash_sw.rs
    kdf_sw.rs
    rng_sw.rs
    mac_sw.rs
    sign_sw.rs
    asymmetric_sw.rs
    key_sw.rs
```

The **CryptoProvider** trait is a façade combining all domain traits. Any provider (software, PKCS#11, HW) implements the same trait set and can be swapped at runtime by type.

Algorithm Naming
----------------
Algorithms are selected by stable string IDs (e.g., `AES-GCM`, `ECDH-P256`). This avoids API churn, centralizes enablement/disablement, and simplifies capability reporting.

Error Handling
--------------
A single `CryptoError` enum provides consistent error mapping across domains (invalid params, unsupported algorithm, encrypt/decrypt errors, signature/verify, RNG, etc.).

Side‑Channel Considerations
---------------------------
- Relies on RustCrypto crates’ constant‑time primitives where applicable.
- Avoids branching on secrets in glue code.
- Uses `zeroize` to wipe key material on deletion.

Extensibility
-------------
- Add new algorithms by extending AlgorithmId constants and mapping in the provider modules.
- Introduce new providers (PKCS#11, HSM/TEE) by implementing the existing trait set.

