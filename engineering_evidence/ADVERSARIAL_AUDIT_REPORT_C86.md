# Adversarial Audit Report - Alpha-C86

## Verified Tamper & Forgery Rejections
1. RFC 8032 Section 7.1 official Test Vector 1 & Test Vector 2 pass bit-exact public key, signature, and bit-flip rejection checks.
2. Wrong Ed25519 public key and 1-bit DSSE payload mutations fail verification with `INVALID_ED25519_SIGNATURE`.
3. Output ELF binary byte tampering fails verification with `SUBJECT_DIGEST_MISMATCH_app.elf`.
4. CycloneDX SBOM mutation fails verification with `SBOM_DIGEST_MISMATCH`.
