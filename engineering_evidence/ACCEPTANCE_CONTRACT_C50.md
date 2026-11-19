# ACCEPTANCE CONTRACT — Alpha-C50: Elementwise Vector Store (`store_off`) 4-Lane Strip-Mining, Runtime Alias Guard & Live Wasmtime Linear Memory Execution

**Cycle:** Alpha-C50  
**Repository:** `F:\repository-compiler` (`OmniCompiler`)  
**Verdict:** **APPROVED & EMPIRICALLY VERIFIED**

---

## 1. Delivered Invariants
1. **Elementwise Array/Struct Write Vectorization (`compiler/loop_vectorizer.py`):**
   - Extracted shared `_match_zero_based_unit_loop`, `_resolve_linear_offset` (supporting shifted index offsets `base + (i + c) * stride`), and `_has_escaped_loop_uses` for sound loop matching across both reductions and elementwise stores.
   - Implemented `LoopVectorizerPass._match_struct_array_store` and `_rewrite_struct_array_store_4x` (reporting `stats["vectorized_stores"]` and feeding `vectorize_vla_function`):
     - Performs backward expression slicing from `store_val` over pure trap-free SSA DAG opcodes (`_PURE_VECTOR_DAG_OPCODES`), supporting binary maps (`dst[i] = a[i] + b[i]`), index-dependent formulas (`dst[i] = dst[i] * 3 + i`), and constant fills (`dst[i] = 42`).
     - Emits 4 parallel `load_off` lanes BEFORE any 4-lane arithmetic or `store_off`, preserving exact in-place (`dst == src`) semantics.
     - Automatically emits a runtime pointer non-overlap / exact-equality guard (`chunks_v = select(all_ok, raw_chunks, 0)`, `tail_start = shl(chunks_v, 2)`) that routes partially overlapping pointers (`dst = &src[1]`) cleanly to the scalar tail starting at `0`.
2. **Z3 Bitwise Modeling (`validation/biabduction_verifier.py`):**
   - Extended `_sym_of` with `"and"`, `"or"`, and `"xor"` so runtime alias predicates compose accurately in Z3 `QF_BV` alongside `PROVEN_MEMORY_SAFE` / `BOUND_VIOLATION_REFUTED` verification over `load_off` and `store_off`.
3. **Live Multi-Backend Parity (`Native` / `LLVM O3` / `Wasmtime` / `WSL ELF64`):**
   - Verified bit-exact vector map+reduce execution across x86-64 Native JIT, LLVM O3 JIT, PE64 EXE, ELF64 (WSL2), and LIVE WebAssembly (`wasmtime`) Linear Memory.
