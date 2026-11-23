# Acceptance Contract - Alpha-C86: Cryptographic SLSA Level 3 / in-toto Provenance

## Scope
Create `packaging/slsa_provenance.py` and hook `PackagerEngine.generate_slsa_provenance` into `packaging/packager.py`:
1. Pure-Python RFC 8032 Ed25519 signing/verification + DSSE Pre-Authentication Encoding (`DSSEv1`).
2. in-toto Statement v1 (`https://in-toto.io/Statement/v1`) wrapping SLSA Provenance v1.0 (`https://slsa.dev/provenance/v1`).
3. Cryptographic binding of target binary SHA-256 subject digests, REAPI/CAS `ActionSpec` inputs & `ActionResult` outputs, and CycloneDX v1.5 SBOM SHA-256 digest.

## Empirical Gates
- `python -W error::ResourceWarning run_c86_tests.py` passes RFC 8032 vectors + full tamper checks.
- `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c86_tests.py` -> `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` passes `14/14`.
- Full `unittest discover` passes 100%.
