
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, HKDF_SHA256, HKDF_SHA512};
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

pub fn derive(alg: AlgorithmId, key: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut okm = vec![0u8; out_len];
    if alg == HKDF_SHA256 {
        let hk = Hkdf::<Sha256>::new(None, key);
        hk.expand(info, &mut okm).map_err(|_| CryptoError::ProviderError("HKDF len"))?;
        Ok(okm)
    } else if alg == HKDF_SHA512 {
        let hk = Hkdf::<Sha512>::new(None, key);
        hk.expand(info, &mut okm).map_err(|_| CryptoError::ProviderError("HKDF len"))?;
        Ok(okm)
    } else {
        Err(CryptoError::UnsupportedAlgorithm("kdf"))
    }
}
