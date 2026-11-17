# ACCEPTANCE CONTRACT — Alpha-C37

**Date:** 2026-11-17  
**Milestone:** Alpha-C37  
**Scope:** Z3 SSA Spatial Memory-Bounds & Pointer Disjointness Prover (`BiAbductionVerifier` / CheckedC-Infer Upgrade), Live `SalsaQueryEngine` Incremental Parsing & Lowering Integration in `OmniRepoCompiler`, and Real OS `ctypes.CDLL` Multi-Repo `.dll`/`.so` Execution Proof

---

## Frozen Deliverables & Verification Criteria

1. **Z3 SSA Spatial Memory-Bounds & Pointer Disjointness Verifier (`validation/biabduction_verifier.py`):**
   - `verify_ssa_memory_bounds(ssa_fn, struct_sizes, param_struct_map=None, timeout_ms=800)`:
     - Symbolically reconstructs `load_off` / `store_off` byte-offset expressions (`const`, `add`, `sub`, `mul`, `shl`) plus loop-header upper/lower induction guards (`i < N`, `0 <= i`) into Z3 64-bit arithmetic.
     - Proves `0 <= byte_off && byte_off + access_bytes <= struct_size` for every bounded struct access (safe: `proven=True`, `checks_passed >= 1`), and mathematically refutes out-of-bounds loop strides or offsets with concrete Z3 counterexamples (`proven=False`, `violations` non-empty).
   - `verify_ssa_pointer_disjointness(ssa_fn)`: audits read/write pointer footprints for disjointness vs alias hazards.
   - Integrate bounded struct verification telemetry cleanly into `OmniRepoCompiler` (`results["stages"]["separation_logic"]["z3_bounds_verified"]` / `"z3_bounds_checked"`).

2. **Live `SalsaQueryEngine` Incremental AST & SSA Memoization (`orchestrator/salsa_query_engine.py`, `omni_repo_compiler.py`):**
   - Add per-compiler `self.salsa = SalsaQueryEngine()` caching file-level AST parsing keyed by `(file_path, blake3_digest(source))` so unchanged files across consecutive multi-repo compilations skip re-parsing via BLAKE3 Green verification.
   - Record cache metrics (`salsa_ast_hits`, `salsa_ast_misses`) in `results["stages"]["ingestion"]`.

3. **Real OS Shared Library (`.dll`/`.so`) Execution Proof (`OmniRepoCompiler` `target_format="shared_lib"` + `ctypes.CDLL`):**
   - Verify cross-repo polyglot code (Rust + Go + TypeScript with structs, `[T; N]` arrays, `match`/`switch`, and `.rodata` LUTs) compiles to a standalone `.dll` (Windows) / `.so` (Linux) that loads cleanly via the real OS dynamic loader (`ctypes.CDLL`) and executes with exact numeric & struct-mutation parity.

4. **Mandatory Verification Gates (Pass Criteria):**
   - `tests/test_alpha_c37_z3_bounds_salsa_and_os_cdll.py` via `run_c37_tests.py`:
     1. Z3 proves `TelemetryBatch` (`48` bytes) loop accesses `while i < 4` SAFE (`proven=True`), and refutes an out-of-bounds loop `while i < 5` (`proven=False`, concrete `i=4` counterexample!) + rejects aliasing/OOB mutations cleanly.
     2. Real OS `ctypes.CDLL` execution (with clean `FreeLibrary` / `dlclose` unload) of a multi-repo Rust+Go+TS `.dll` / `.so` using C-ABI structs, `[T; N]` arrays, `match`/`switch`, and `.rodata` LUTs across both Native & LLVM backends.
     3. Live `SalsaQueryEngine` incremental build test across a 3-repo workspace: cold build (3 misses, 0 hits) -> warm/1-file-edited rebuild (2 Green hits, 1 miss, measurable speedup).
     4. Separation-logic multi-pointer disjointness check (`verify_ssa_pointer_disjointness`).
   - `AetherMind_Strict_Auditor.py` returns `APROVADO` on `run_c37_tests.py` and `run_full_regression.py`.
   - `python -W default -m unittest discover -s tests -t F:\repository-compiler` passes 100% (230/230 tests, 0 warnings).
