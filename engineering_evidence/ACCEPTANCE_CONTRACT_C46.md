# ACCEPTANCE CONTRACT — Alpha-C46: Dynamic ELF64 OS Execution & C-ABI Struct Array SIMD Loop Auto-Vectorization (Resolution of `META-P2-VECTORIZER`)

**Target Commit / Tag:** Alpha-C46  
**Auditor:** Strict Empirical Auditor & Adversarial Engineering Protocol  
**Repository:** `F:\repository-compiler` (`OmniCompiler`)  
**Verdict:** **APPROVED & EMPIRICALLY VERIFIED**

---

## 1. Scope & Technical Invariants

### 1.1 Dynamic Linux ELF64 Executable Emission & Execution
1. **Dynamic ELF64 Emission (`StandaloneBinaryEmitter.build_elf64_dynamic_exe`):**
   - Synthesizes `PT_INTERP` pointing to `/lib64/ld-linux-x86-64.so.2`.
   - Synthesizes `PT_DYNAMIC` containing `DT_NEEDED`, `DT_HASH`, `DT_STRTAB`, `DT_SYMTAB`, `DT_STRSZ`, `DT_SYMENT`, `DT_PLTGOT`, `DT_PLTREL`, `DT_PLTRELSZ`, `DT_JMPREL`, `DT_BIND_NOW`, and `DT_FLAGS = DF_BIND_NOW`.
   - Emits `.dynsym` entries (`SHN_UNDEF`), `.rela.plt` relocation records (`R_X86_64_JUMP_SLOT`), and `.got.plt` slots with `GOT[0]` initialized to `vaddr + dynamic_off` per System V AMD64 ABI.
2. **Two-Pass Length-Stable Callable Custom Code:**
   - Supports `custom_code(got_slots, entry_vaddr)` callable that probes with dummy GOT slots to fix code length, then resolves RIP-relative displacements to exact runtime GOT slots.
3. **Live Linux OS Execution:**
   - Live execution on Linux (native POSIX / WSL Ubuntu 2): dynamically resolves `libc.so.6!abs(-137)` and terminates with return code `137`.
4. **Unified API (`StandaloneBinaryEmitter.emit_dynamic_executable`):**
   - Seamlessly emits dynamic multi-DLL PE32+ executables on Windows and dynamic ELF64 executables on Linux with verified import tables.

### 1.2 C-ABI Struct Array SIMD Auto-Vectorization (`META-P2-VECTORIZER`)
1. **LoopVectorizerPass Recognition:**
   - Detects inductive loops (`while i < N`) over contiguous struct array fields (`load_off base, base_off + i * stride, width`) accumulating into a scalar sum (`fadd` / `add`).
   - Guards against loop bodies with memory modifications (`store` / `store_off`), preserving side-effecting loops for native execution while safely auto-vectorizing pure reductions.
2. **Balanced SIMD Tree Reduction Lowering:**
   - Replaces the loop header, condition, body, induction increment, and branch with straight-line parallel loads and a balanced logarithmic tree reduction (`(v0 + v1) + (v2 + v3)`).
   - Preserves non-zero initial accumulator values from pre-headers (`init_val + tree_sum`).
3. **Multi-Backend Parity & Execution:**
   - Lowers cleanly across Native W^X JIT, LLVM O3 JIT, and WASM backends.
   - Tested execution parity: `SignalBuffer.samples[0..3] = [10.25, 20.50, 30.75, 40.50]` returns exact bit-identical `102.0` on both Native and LLVM JIT.
4. **Continuous Metacognition Resolution:**
   - In 9-repo stress benchmark (`benchmarks/stress_metacognition_c40.py`), `vectorized_loops` increased from `0` to `8`.
   - `META-P2-VECTORIZER` is completely cleared from active improvement goals.

---

## 2. Test Verification Matrix
| Test Case | Description | Result |
| :--- | :--- | :--- |
| `test_01_dynamic_elf_emission_and_structure` | ELF64 header, PT_INTERP, PT_DYNAMIC, DT_NEEDED, DT_BIND_NOW audit | **PASS** |
| `test_02_dynamic_elf_callable_custom_code_two_pass` | Callable custom_code RIP-relative GOT slot dereference | **PASS** |
| `test_03_live_linux_execution_via_wsl_or_subprocess` | Live Linux execution: `libc.so.6!abs(-137)` returns exit code 137 | **PASS** |
| `test_04_emit_dynamic_executable_unified_api` | Cross-platform PE multi-import & ELF dynamic executable emission | **PASS** |
| `test_05_struct_array_loop_vectorization` | Detection & rewriting of `pkt.weights[i]` loop into balanced SIMD tree | **PASS** |
| `test_06_vectorized_struct_array_execution_parity_native_llvm` | Multi-backend parity: Native JIT & LLVM JIT both compute exact `102.0` | **PASS** |

Full suite discover: **245/245 PASS** (88.36s).
