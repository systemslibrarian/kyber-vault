# kyber-vault

Browser demo for ML-KEM (CRYSTALS-Kyber), the post-quantum key encapsulation mechanism standardized as NIST FIPS 203 in August 2024.

## Post-Quantum KEM Catalog Entry

| Field | Value |
|---|---|
| Scheme | ML-KEM (CRYSTALS-Kyber) |
| Standard | NIST FIPS 203 (August 2024) |
| Hardness | Module Learning With Errors (Module-LWE) |
| Parameter sets | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| Public key sizes | 800 / 1,184 / 1,568 bytes |
| Shared secret | Always 32 bytes (256-bit) |
| Quantum resistance | Yes - Grover reduces to 128/192/256-bit effective security |
| Deployed in | Chrome 124+, Cloudflare, AWS, Signal, iCloud |
| Standardized | August 2024 |

## Cross-References in crypto-compare

- iron-serpent: ML-KEM for key encapsulation + Serpent-256-CTR for data encryption = complete post-quantum hybrid encryption system.
- sphincs-ledger: ML-KEM (key encapsulation) + SLH-DSA (signatures) = complete post-quantum public-key cryptography suite.
- quantum-vault-kpqc: Korean KpqC (SMAUG-T) is an alternative post-quantum KEM for the same role, with an independent national standardization track.
- ratchet-wire: Signal's PQXDH uses X25519 + ML-KEM-1024 to provide post-quantum forward secrecy.

## Demo

**[Live demo](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)**

Implementation lives in `demos/kyber-vault`.