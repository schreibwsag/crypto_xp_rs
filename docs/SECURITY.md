
# SECURITY

Threat Model (High Level)
-------------------------
- Keys must **not** be exposed via API (private SymKey fields; explicit delete + zeroize).
- AEAD nonces must be unique per key; callers are responsible for nonce generation.
- OS entropy availability is assumed for seeding ChaCha20Rng.
- Provider memory is in the application address space (software provider). For stronger isolation, use a PKCS#11 or TEE/HSM provider.

Hardening Guidance
------------------
- Disable debug logs in production; never log secrets.
- Use process/container sandboxing.
- Consider pinning CPU frequency or adding jitter if you suspect microarchitectural side channels.
- Use constant‑time comparison for tags/signatures (handled by underlying crates).

Key Management
--------------
- Import keys through KeyManagement only; zeroize on deletion.
- Store long‑term keys in a secure keystore (PKCS#11/HSM) and keep application keys ephemeral where possible.

PQC Readiness
-------------
- API is algorithm‑name based and provider‑pluggable, so adding PQC (e.g., KEM + Dilithium‑like sigs) can be done by introducing new AlgorithmId entries and a provider that implements them.

