# kyber-vault demo

`kyber-vault` is a browser-based ML-KEM (CRYSTALS-Kyber) educational demo for the `crypto-compare` portfolio.

## What This Demo Shows

- Encapsulation and decapsulation workflow for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- LWE arithmetic visualizer (`b = As + e (mod q)`) with an educational small-modulus matrix display.
- Hybrid encryption flow: ML-KEM key encapsulation + HKDF-SHA256 + AES-256-GCM.
- Benchmark runner for KeyGen/Encaps/Decaps and X25519 ECDH comparison.

## Live Demo

**[https://systemslibrarian.github.io/crypto-lab-kyber-vault/](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)**

## Run Locally

```bash
npm install
npm run dev
```

## ML-KEM Implementation Source

- Package: `@noble/post-quantum`
- Version: `0.6.0` (installed from npm)
- Exports used: `ml_kem512`, `ml_kem768`, `ml_kem1024` with `keygen`, `encapsulate`, `decapsulate`
- Package existence/API verified via `npm view` and installed module type definitions

## FIPS 203 Reference

Authoritative specification:

- NIST FIPS 203 (August 2024): https://csrc.nist.gov/pubs/fips/203/final
- CRYSTALS-Kyber resources: https://pq-crystals.org/kyber/

Parameter byte sizes in this demo match FIPS 203 parameter set table values:

- ML-KEM-512: public key 800, private key 1632, ciphertext 768, shared secret 32
- ML-KEM-768: public key 1184, private key 2400, ciphertext 1088, shared secret 32
- ML-KEM-1024: public key 1568, private key 3168, ciphertext 1568, shared secret 32

## Security Note: Implicit Rejection

ML-KEM decapsulation is designed for implicit rejection behavior. When ciphertext or secret key material is incorrect, decapsulation returns a pseudorandom-looking shared secret instead of raising an explicit decryption error. In this demo, integrity failure is surfaced by AES-GCM authentication failure in the hybrid layer.

## Offline Runtime

The app is fully local after `npm install`; no external CDN resources are required at runtime.
