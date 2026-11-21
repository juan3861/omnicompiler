# Acceptance Contract — Alpha-C64: Hardware CPUID, VEX FMA, EVEX AVX-512 & Dual-Target GCC

## 1. Objective
Complete the tri/quad-ecosystem compiler architecture with real x86-64 hardware CPUID/XGETBV feature discovery, 256-bit hardware FMA (`vfmadd213pd` / `vfmadd213ps` / `vfmadd213sd`) vector and scalar execution, 512-bit EVEX AVX-512 code generation verified via GNU `objdump` and CPUID-gated execution, and Canary-verified Dual-ABI `GCCBackend` (ELF64 SysV + Windows PE/COFF).

## 2. Acceptance Criteria
1. `detect_host_simd_features()` probes `CPUID` leaves `1` and `7,0` plus `XGETBV(0)` natively in W^X memory without crashing on non-AVX-512 hosts.
2. `NativeJitCompiler.compile_avx2_fma_pd()` and `X64CodeGenerator` emit and physically execute `vfmadd213pd`/`vfmadd213sd`, reaching differential consensus with LLVM 20 O3, GCC `-O3 -mfma`, and Wasmtime `v128`.
3. `emit_avx512_evex_vec_add_i64()` and `emit_avx512_evex_fma_pd()` emit valid 4-byte EVEX (`0x62`) `zmm` encodings verified by `objdump` disassembly and guarded by `detect_host_simd_features()["avx512f"]`.
4. `GCCBackend` maintains fail-closed canary gating across `supports_elf64` and `supports_windows_coff`, and `OmniRepoCompiler` propagates `host_simd_features` and CPUID-matched `vla_simd_metadata`.
