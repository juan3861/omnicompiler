# Adversarial Audit Report: Alpha-C95

## Scope Audited
- **Files Modified / Added:**
  - `compiler/binary_emitter.py`: Dynamic `.idata` IAT emission (with `SizeOfHeaders` dynamic file-alignment fix for 4-section PE DLLs), ELF64 x86-64/ARM64 `.got.plt` + `.rela.plt` (`R_X86_64_JUMP_SLOT` / `R_AARCH64_JUMP_SLOT`) + `DT_NEEDED` + `DF_BIND_NOW`, Mach-O 64 `LC_LOAD_DYLIB` + `LC_DYLD_INFO_ONLY` bind opcodes + Ad-Hoc CodeSign, and `emit_shared_library` `arm64_elf_so` routing.
  - `compiler/object_linker.py`: `emit_linked_shared_library` wiring `external_os_imports` and `OS_C_ABI_IMPORT_TABLE`.
  - `omni_repo_compiler.py`: Linux ARM64 `shared_lib` routing (`arm64_elf_so` + DWARF sections).
  - `compiler/ssa_ir.py` & `compiler/stack_promotion.py`: Local `AnnAssign` struct type propagation & non-escaping `omni_alloc` stack `alloca` promotion.
  - `frontends/polyglot_ssa_lowering.py`: Fixed local arrays (`[...]`, `[val; N]`, Go `[]int64{...}`, C `T arr[N] = {...}`), `.len()`/`.length`, struct literal construction, inline closures/lambdas (`|k| ...`, `(z) => ...`, `func(...) { ... }`), cross-module `import` / `use` / `#include` capture & qualified module calls.
  - `tests/test_alpha_c95_real_oss_workloads.py` & `run_c95_tests.py`.

## Adversarial Checks & Empirical Bugs Caught & Resolved
1. **PE64 DLL 4-Section Header Overflow Bug (Caught & Fixed):**
   - Initial live `ctypes.CDLL` test of a 4-section PE32+ DLL (`.text`, `.edata`, `.idata`, `.pdata`) failed with `OSError: [WinError 1114]` and `pefile` reported broken RVAs at `0x2000`.
   - Root cause: 4 section headers pushed total PE header size to `536` bytes (`> 0x200` `file_align`), shifting section file offsets without updating `SizeOfHeaders` and `cur_file_ptr`.
   - Fix: Computed `size_of_headers = self._align_up(376 + 40 * num_sections, file_align)` dynamically in `build_pe64_dll`. Live `ctypes.CDLL` execution invoking `MSVCRT.dll!malloc`/`free` immediately passed (`dyn_oss_probe(12) == 127`).
2. **Polyglot `for` Loop Variable Initializer Regression (Caught & Fixed):**
   - Expanding `_parse_var_decl()` to return `List[ast.stmt]` (for multi-statement struct initializers) caused `_parse_for_stmt` (`init_stmts.append(self._parse_var_decl())`) to nest a list inside `init_stmts`, causing `test_alpha_c27` (`ts_poly_chain`) to fail with `100 != 88`.
   - Fix: Switched line 2383 in `_parse_for_stmt` to `init_stmts.extend(self._parse_var_decl())`. Verified `test_alpha_c27`, `c33`, `c74` passing (`11/11 OK`).
3. **Cross-Language Shared-Library Execution Verification:**
   - Compiled 4 heterogeneous repositories (`C + Go + Rust + TypeScript`) using local structs, fixed arrays, inline lambdas, cross-module calls, and `malloc`/`free` into a single native shared library and executed `ts_real_oss_entry(v)` live via `ctypes.CDLL` across `v in (0, 6, -5, 19)` (`4*v + 126` verified bit-exact).

## Empirical Gate Results (Locally Verified)
- `python -W error::ResourceWarning run_c95_tests.py`: **3/3 OK** (`17.452s`, exit code `0`).
- `python AetherMind_Strict_Auditor.py run_c95_tests.py`: **APROVADO** (exit code `0`).
- `python -W error::ResourceWarning test_empirical_audit.py`: **14/14 PASS**.
- `python -W default -m unittest discover -s tests -p "test_*.py"`: **411/411 OK** (`460.264s`, exit code `0`).
