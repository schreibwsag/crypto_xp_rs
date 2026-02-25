
# TLS 1.3 Integration Notes (with rustls)

This library focuses on cryptographic primitives and provider abstraction. To
use with TLS 1.3 (e.g., rustls):

- rustls manages most cryptography internally but allows custom signers and
  key exchange via trait implementations in certain places (versions may vary).
- You can wrap a provider-backed key (e.g., ECDSA P‑256) behind a signer object
  that rustls accepts, forwarding `sign()` to your provider.
- For ECDH, derive shared secrets using your provider and feed the result into
  the TLS key schedule as required by rustls APIs.

Check rustls version docs for the exact extension points. Keep key material out
of application logs and avoid copying long‑term secrets into process memory when
using HSM/PKCS#11 providers.
