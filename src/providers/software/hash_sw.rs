
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, SHA2_256, SHA2_512, SHA3_256, SHA3_512};
use sha2::{Sha256, Sha512, Digest as _};
// use sha3::{Sha3_256, Sha3_512, Digest as _};
use sha3::{Sha3_256, Sha3_512};

pub fn hash(alg: AlgorithmId, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if alg == SHA2_256 { Ok(Sha256::digest(data).to_vec()) }
    else if alg == SHA2_512 { Ok(Sha512::digest(data).to_vec()) }
    else if alg == SHA3_256 { Ok(Sha3_256::digest(data).to_vec()) }
    else if alg == SHA3_512 { Ok(Sha3_512::digest(data).to_vec()) }
    else { Err(CryptoError::UnsupportedAlgorithm("hash")) }
}
