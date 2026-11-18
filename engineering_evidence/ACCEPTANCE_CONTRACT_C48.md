# ACCEPTANCE CONTRACT — Alpha-C48: Variadic OS ABI (`printf` Win64/SysV `%al`), ARM64 Dynamic ELF64 (`ADRP+LDR+BR`), Mach-O `LC_LOAD_DYLIB` & VLA 4x Strip-Mining Vectorizer

**Cycle:** Alpha-C48  
**Repository:** `F:\repository-compiler` (`OmniCompiler`)  
**Verdict:** **APPROVED & EMPIRICALLY VERIFIED**

---

## 1. Delivered Invariants
1. **Variadic OS ABI Across Native & LLVM O3 (`printf` with Mixed `i64` + `f64`):**
   - `compiler/native_codegen.py`: Set `%al = min(8, c_fp)` under SysV AMD64 ABI (`Linux`) before external `call`, and mirrored floating-point arguments `0..3` into both `XMM` and corresponding Win64 integer registers (`rcx`/`rdx`/`r8`/`r9`) for `MSVCRT.dll` varargs compliance.
   - `compiler/llvm_backend.py`: Emits variadic declarations `declare i64 @printf(i64, ...)` and variadic calls `call i64 (i64, ...) @printf(...)` via `_format_external_decl`, enabling multiple variadic signatures in the same LLVM module.
   - `validation/backend_translation_validator.py`: Extended LLVM `call` lifter regex to accept optional variadic type signatures `(i64, ...)`.
2. **ARM64 (AArch64) Dynamic ELF64 & Formal Linker Integration:**
   - `compiler/binary_emitter.py`: Parameterized `build_elf64_dynamic_exe(..., arch=...)` for `AArch64` (`e_machine = 183`, `/lib/ld-linux-aarch64.so.1`, `R_AARCH64_JUMP_SLOT = 1026`), added `_encode_a64_got_stub` (`ADRP X16 + LDR X17 + BR X17`), and wired `arm64_elf` dynamic executable linking with `libc.so.6!exit` teardown.
   - `compiler/object_linker.py`: Added 12-byte ARM64 Unicorn-safe OS stubs (`MOVZ X0, #0x9800; MOVK X0, #0x0200, LSL #16; RET` for allocators; `MOVZ W0, #0; RET; NOP` for generic OS calls) when linking `ARM64_CALL26` modules.
   - `validation/binary_structure_auditor.py`: Fixed `audit_elf` fallback `.dynsym` loop bound via `DT_HASH.nchain`, separated `SHN_UNDEF` imports (`st_shndx == 0`) from exports, and extracted `DT_NEEDED` into `metrics["needed_libs"]`.
3. **Mach-O 64-bit `LC_LOAD_DYLIB` + External Symbol Table + XNU Ad-Hoc CodeSign:**
   - `compiler/binary_emitter.py`: Extended `build_macho64(..., load_dylibs=..., imported_symbols=...)` to emit `LC_LOAD_DYLINKER` (`/usr/lib/dyld`), `LC_LOAD_DYLIB` (`0x0C`), and `LC_SYMTAB` external `N_UNDF | N_EXT` (`_sym`) entries in `__LINKEDIT`, recomputing ARM64 SHA-256 `CodeDirectory` hashes over the full image.
   - `validation/binary_structure_auditor.py`: Extended `audit_macho` to verify and extract `LC_LOAD_DYLIB` and `N_UNDF` symbols into `imported_symbols`.
4. **VLA 4-Lane Strip-Mining Loop Vectorizer (`64 < N <= 4096`):**
   - `compiler/loop_vectorizer.py`: Eliminated duplicate body block scanning (`b is not body_bb`), unified SSA float reduction types to `"f64"`, extracted `_tree_reduce_ssa`, and implemented `_rewrite_struct_array_strip_mined_4x` converting scalar reduction loops above 64 iterations into 4-way ILP strip-mined chunk loops (`0 <= chunk_i < N // 4`) plus exact remainder tail folding.
