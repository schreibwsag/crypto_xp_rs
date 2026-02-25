
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, CHACHA20_RNG};
use rand_chacha::ChaCha20Rng;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand::RngCore;

pub fn random(alg: AlgorithmId, out_len: usize) -> Result<Vec<u8>, CryptoError> {
    if alg != CHACHA20_RNG { return Err(CryptoError::UnsupportedAlgorithm("rng")); }
    let mut rng = ChaCha20Rng::from_rng(OsRng).map_err(|_| CryptoError::RandomError)?;
    let mut out = vec![0u8; out_len];
    rng.fill_bytes(&mut out);
    Ok(out)
}
