// Algorithm ID + provider trait
#[derive(Clone,Debug,PartialEq,Eq,Hash)]
pub struct AlgorithmId(pub &'static str);

pub const AES_CBC:AlgorithmId=AlgorithmId("AES-CBC");
pub const AES_GCM:AlgorithmId=AlgorithmId("AES-GCM");
pub const AES_CCM:AlgorithmId=AlgorithmId("AES-CCM");
pub const CHACHA20_POLY1305:AlgorithmId=AlgorithmId("CHACHA20-POLY1305");

pub const SHA2_256:AlgorithmId=AlgorithmId("SHA2-256");
pub const SHA2_512:AlgorithmId=AlgorithmId("SHA2-512");
pub const SHA3_256:AlgorithmId=AlgorithmId("SHA3-256");
pub const SHA3_512:AlgorithmId=AlgorithmId("SHA3-512");

pub const HKDF_SHA256:AlgorithmId=AlgorithmId("HKDF-SHA256");
pub const HKDF_SHA512:AlgorithmId=AlgorithmId("HKDF-SHA512");

pub const HMAC_SHA256:AlgorithmId=AlgorithmId("HMAC-SHA256");
pub const HMAC_SHA512:AlgorithmId=AlgorithmId("HMAC-SHA512");

pub const ECDH_P256:AlgorithmId=AlgorithmId("ECDH-P256");
pub const ECDSA_P256:AlgorithmId=AlgorithmId("ECDSA-P256");

pub const CHACHA20_RNG:AlgorithmId=AlgorithmId("CHACHA20-RNG");

use crate::api::{symmetric::SymmetricCrypto, asymmetric::AsymmetricCrypto, sign::SignatureCrypto, hash::HashCrypto, kdf::KdfCrypto, rng::RngCrypto, key::KeyManagement, mac::MacCrypto};

pub trait CryptoProvider:
 SymmetricCrypto+AsymmetricCrypto+SignatureCrypto+HashCrypto+KdfCrypto+RngCrypto+KeyManagement+MacCrypto+Send+Sync{
 fn name(&self)->&'static str;
}
