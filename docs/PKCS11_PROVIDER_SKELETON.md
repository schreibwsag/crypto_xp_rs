
# PKCS#11 Provider Skeleton (Design Notes)

- Use a PKCS#11 crate/binding to load a module (shared library) and open a
  session against your token.
- Map AlgorithmId names to PKCS#11 mechanisms (e.g., CKM_AES_GCM, CKM_ECDH1_DERIVE, CKM_ECDSA).
- Implement the same trait set as SoftwareProvider, but operations are forwarded
  to the token (with appropriate key handles/object IDs).
- Keys should be generated/imported inside the token and referenced by handles;
  do not export private key bytes.
- Return `UnsupportedAlgorithm` for mechanisms not available on the token.
- Add capability discovery to print which AlgorithmIds this provider supports.
