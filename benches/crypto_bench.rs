use criterion::{criterion_group, criterion_main, Criterion, black_box};
use crypto_full::SoftwareProvider;
use crypto_full::api::provider::*;
use crypto_full::api::symmetric::{SymmetricCrypto, SymKey};
use crypto_full::api::key::KeyManagement;
use crypto_full::api::hash::HashCrypto;

fn bench_aes_gcm(c: &mut Criterion) {
    let p = SoftwareProvider::new();
    let key: SymKey = p.import_symmetric(&[0u8; 32]).unwrap();
    let iv = [0u8; 12];
    let msg = vec![0u8; 1024];

    c.bench_function("AES-GCM encrypt 1KiB", |b: &mut criterion::Bencher| {
        b.iter(|| {
            let ct = p.encrypt(AES_GCM, &key, &iv, black_box(&msg)).unwrap();
            black_box(ct)
        })
    });
}

fn bench_sha256(c: &mut Criterion) {
    let p = SoftwareProvider::new();
    let msg = vec![0u8; 4096];

    c.bench_function("SHA2-256 hash 4KiB", |b: &mut criterion::Bencher| {
        b.iter(|| {
            let h = p.hash(SHA2_256, black_box(&msg)).unwrap();
            black_box(h)
        })
    });
}

criterion_group!(benches, bench_aes_gcm, bench_sha256);
criterion_main!(benches);

