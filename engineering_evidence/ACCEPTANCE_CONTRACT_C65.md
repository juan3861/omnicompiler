# Acceptance Contract — Alpha-C65: 512-bit EVEX Loop Auto-Fusion, FMA Dot-Product, Persistent Homeostasis PGO & Quad Benchmarks

## 1. Objective
Close the engineering ceiling with automatic 512-bit ZMM EVEX store/FMA fusion in `X64CodeGenerator`, 256-bit `vfmadd231pd` dot-product hardware reduction, persistent SQLite PGO profile calibration (`HomeostasisProfileStore`), and full quad-ecosystem comparative CI benchmarks.

## 2. Hard Gates
1. `X64CodeGenerator` fuses 8 contiguous 64-bit stores (`i64` arithmetic & `f64` FMA) into EVEX 512-bit ZMM sequences verified by `/usr/bin/objdump` and hardware silicon execution on AVX-512F hosts.
2. `NativeJitCompiler.compile_avx2_fma_dot_pd()` executes `vfmadd231pd` + horizontal collapse + `vfmadd231sd` tail matching high-precision Python reference.
3. `HomeostasisProfileStore` persists engine latency, SIMD counts, and divergence penalties across router/compiler restarts and blacklists previously diverging engines.
4. `comparative_benchmark.py` publishes live timings across `omni_native_jit`, `llvm_o3_jit`, `gcc_o3`, `wasmtime_sandbox`, and `homeostasis_quad`.
5. `AetherMind_Strict_Auditor.py` (`APROVADO`), full `unittest discover`, `test_empirical_audit.py` (`14/14`), and CI (`ubuntu-latest` + `windows-latest`) pass 100%.
