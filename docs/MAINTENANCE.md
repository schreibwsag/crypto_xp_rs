
# MAINTENANCE / ALGORITHM UPDATE STRATEGY

- Keep RustCrypto crates at compatible major/minor versions across AEAD/MAC/hash.
- When a crate yanks old versions, update dependent crates simultaneously.
- Add new AlgorithmIds instead of changing existing names to preserve API stability.
- Use feature flags if you later need optional algorithms.

Benchmarks
----------
- Criterion benches (A4) provide a portable perf view across systems.
- Track KPIs for throughput (bytes/sec) and latency (ns/op) over time.

