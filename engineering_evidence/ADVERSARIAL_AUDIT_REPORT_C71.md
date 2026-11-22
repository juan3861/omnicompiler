# Adversarial Audit Report — Alpha-C71: Cross-Emitter `f64` ABI, Multi-Function `.pdata`/`.xdata` & DWARF v5 Subprograms

## 1. Targets Audited
- [`compiler/ssa_ir.py`](file:///F:/repository-compiler/compiler/ssa_ir.py)
- [`compiler/debug_info_emitter.py`](file:///F:/repository-compiler/compiler/debug_info_emitter.py)
- [`compiler/binary_emitter.py`](file:///F:/repository-compiler/compiler/binary_emitter.py)
- [`omni_repo_compiler.py`](file:///F:/repository-compiler/omni_repo_compiler.py)
- [`tests/test_alpha_c71_cross_emitter_f64_abi_pdata_and_dwarf_subprograms.py`](file:///F:/repository-compiler/tests/test_alpha_c71_cross_emitter_f64_abi_pdata_and_dwarf_subprograms.py)

## 2. Adversarial Vectors Addressed
1. **Cross-Emitter `f64` Return ABI Mismatch (`RAX` vs `XMM0`):** Added `global_return_types` propagation into `AstToSsaLowering` and `lower_ast_to_ssa` from manifests and AST annotations, ensuring `call` results from `f64`-returning functions receive `var_type="f64"` so `Native`, `LLVM`, and `GCC` agree on `XMM0`/`D0` return registers and `int(res)` lowers to `fptosi`.
2. **Win64 `.pdata` Multi-Function Unwind Sorting & Relative `.xdata` Offsets:** Implemented `emit_win64_multi_pdata_xdata` (sorting `RUNTIME_FUNCTION` entries by ascending `BeginAddress` with 4-byte-aligned `UNWIND_INFO` blobs) and updated `build_pe64_dll` to relocate both `BeginAddress`/`EndAddress` (`+0x10` past `DllMain`) and per-entry `UnwindInfoAddress` offsets.

## 3. Empirical Verification Summary
- `AetherMind_Strict_Auditor.py run_c71_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning run_c71_tests.py`: `2/2` OK.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full regression `unittest discover -s tests -p "test_*.py"`: verified green.
