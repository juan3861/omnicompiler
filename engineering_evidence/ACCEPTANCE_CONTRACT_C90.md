# Acceptance Contract - Alpha-C90: DWARF CFI `.eh_frame`, Async Coroutines & OSS E2E

## Scope
1. Implement `DwarfCFIFrameEmitter` in `compiler/debug_info_emitter.py` emitting DWARF CFI `.eh_frame` (CIE + FDEs) and wire into `OmniRepoCompiler` ELF emission.
2. Implement `compiler/async_coroutine_lowering.py` (`AsyncCoroutineLowerer` + `drive_compiled_coroutine`) lowering `async def` / `await` to zero-allocation resumable SSA state machines compiled to native machine code.
3. End-to-end verification unifying 4-repo polyglot compilation, `.eh_frame` unwind decoding via `pyelftools`, RBE BwoB DAG execution, and SLSA Level 3 Ed25519 provenance attestation.

## Empirical Gates
- `python -W error::ResourceWarning run_c90_tests.py` passes 100%.
- `AetherMind_Strict_Auditor.py run_c90_tests.py` -> `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` passes `14/14`.
- Complete `unittest discover` passes 100%, and all 4 GitHub Actions runners pass.
