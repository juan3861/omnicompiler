# Acceptance Contract — Alpha-C77 (Hermetic CAS, Multi-Node RBE & Bit-for-Bit Reproducibility)

## Scope
1. `orchestrator/rbe_cas.py`: `ContentAddressableStore` (SHA-256 blob store + `ActionCache`), `HermeticSandboxExecutor` (isolated directories + deterministic env), `RBEWorkerNode` (HTTP/TCP workers), `RBECoordinator` (DAG scheduler).
2. `orchestrator/persistent_salsa_cache.py`: `attach_cas`, `put_cas_artifact`, `get_cas_artifact`.

## Verification Gates
- `run_c77_tests.py -W error::ResourceWarning`: `2/2 OK`.
- `AetherMind_Strict_Auditor.py run_c77_tests.py`: `APROVADO`.
