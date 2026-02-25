
pub mod symmetric_sw;
pub mod hash_sw;
pub mod rng_sw;
pub mod kdf_sw;
pub mod sign_sw;
pub mod asymmetric_sw;
pub mod mac_sw;
pub mod key_sw;

use crate::api::provider::CryptoProvider;
use crate::api::{
    symmetric::SymmetricCrypto,
    asymmetric::AsymmetricCrypto,
    sign::SignatureCrypto,
    hash::HashCrypto,
    kdf::KdfCrypto,
    rng::RngCrypto,
    key::KeyManagement,
    mac::MacCrypto,
};

#[derive(Default)]
pub struct SoftwareProvider;

impl SoftwareProvider { pub fn new() -> Self { Self } }

impl CryptoProvider for SoftwareProvider { fn name(&self) -> &'static str { "software" } }

impl SymmetricCrypto for SoftwareProvider {
    fn encrypt(&self, alg: crate::api::provider::AlgorithmId, key: &crate::api::symmetric::SymKey, iv: &[u8], plaintext: &[u8])
        -> Result<Vec<u8>, crate::errors::CryptoError>
    { symmetric_sw::encrypt(alg, &key.opaque, iv, plaintext) }
    fn decrypt(&self, alg: crate::api::provider::AlgorithmId, key: &crate::api::symmetric::SymKey, iv: &[u8], ciphertext: &[u8])
        -> Result<Vec<u8>, crate::errors::CryptoError>
    { symmetric_sw::decrypt(alg, &key.opaque, iv, ciphertext) }
}

impl HashCrypto for SoftwareProvider {
    fn hash(&self, alg: crate::api::provider::AlgorithmId, data: &[u8]) -> Result<Vec<u8>, crate::errors::CryptoError> {
        hash_sw::hash(alg, data)
    }
}

impl RngCrypto for SoftwareProvider {
    fn random(&self, alg: crate::api::provider::AlgorithmId, out_len: usize) -> Result<Vec<u8>, crate::errors::CryptoError> {
        rng_sw::random(alg, out_len)
    }
}

impl KdfCrypto for SoftwareProvider {
    fn derive(&self, alg: crate::api::provider::AlgorithmId, key: &[u8], info: &[u8], out_len: usize)
        -> Result<Vec<u8>, crate::errors::CryptoError> {
        kdf_sw::derive(alg, key, info, out_len)
    }
}

impl SignatureCrypto for SoftwareProvider {
    fn sign(&self, alg: crate::api::provider::AlgorithmId, private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, crate::errors::CryptoError> {
        sign_sw::sign(alg, private_key, msg)
    }
    fn verify(&self, alg: crate::api::provider::AlgorithmId, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, crate::errors::CryptoError> {
        sign_sw::verify(alg, public_key, msg, signature)
    }
}

impl AsymmetricCrypto for SoftwareProvider {
    fn generate_keypair(&self, alg: crate::api::provider::AlgorithmId) -> Result<crate::api::asymmetric::AsymKeyPair, crate::errors::CryptoError> {
        asymmetric_sw::generate_keypair(alg)
    }
    fn ecdh(&self, alg: crate::api::provider::AlgorithmId, private_key: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, crate::errors::CryptoError> {
        asymmetric_sw::ecdh(alg, private_key, peer_public)
    }
}

impl MacCrypto for SoftwareProvider {
    fn mac(&self, alg: crate::api::provider::AlgorithmId, key: &[u8], data: &[u8]) -> Result<Vec<u8>, crate::errors::CryptoError> {
        mac_sw::mac(alg, key, data)
    }
    fn mac_verify(&self, alg: crate::api::provider::AlgorithmId, key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool, crate::errors::CryptoError> {
        mac_sw::mac_verify(alg, key, data, tag)
    }
}

impl KeyManagement for SoftwareProvider {
    fn import_symmetric(&self, data: &[u8]) -> Result<crate::api::symmetric::SymKey, crate::errors::CryptoError> {
        key_sw::import_symmetric(data)
    }
    fn delete_symmetric(&self, key: &mut crate::api::symmetric::SymKey) -> Result<(), crate::errors::CryptoError> {
        key_sw::delete_symmetric(key)
    }
    fn import_private_key(&self, data: &[u8]) -> Result<Vec<u8>, crate::errors::CryptoError> {
        key_sw::import_private_key(data)
    }
    fn delete_private_key(&self, key: &mut Vec<u8>) -> Result<(), crate::errors::CryptoError> {
        key_sw::delete_private_key(key)
    }
}
