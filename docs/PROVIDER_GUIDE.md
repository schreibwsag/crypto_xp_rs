
# PROVIDER GUIDE

To add another provider (e.g., PKCS#11, HW accelerator):

1) Create a new module under `providers/<name>/`.
2) Implement all domain traits used by `CryptoProvider`:
   - SymmetricCrypto
   - HashCrypto
   - KdfCrypto
   - RngCrypto
   - MacCrypto
   - SignatureCrypto
   - AsymmetricCrypto
   - KeyManagement
3) Implement `CryptoProvider for <YourProvider>` with `fn name(&self) -> &'static str`.

Testing a New Provider
----------------------
- Reuse the A3 tests by aliasing `type TestProvider = <YourProvider>` and running the same suites.
- Provide capability checks if not all algorithms are implemented; return `UnsupportedAlgorithm` for not‑supported ones.

