
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, ECDSA_P256};
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};

pub fn sign(alg: AlgorithmId, private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if alg != ECDSA_P256 { return Err(CryptoError::UnsupportedAlgorithm("sign")); }
    let sk = SigningKey::from_slice(private_key).map_err(|_| CryptoError::SignatureError)?;
    let sig: Signature = sk.sign(msg);
    Ok(sig.to_der().as_bytes().to_vec())
}

pub fn verify(alg: AlgorithmId, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    if alg != ECDSA_P256 { return Err(CryptoError::UnsupportedAlgorithm("verify")); }
    let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::VerifyError)?;
    let sig = Signature::from_der(signature).map_err(|_| CryptoError::VerifyError)?;
    Ok(vk.verify(msg, &sig).is_ok())
}
