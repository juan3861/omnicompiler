# Acceptance Contract — Alpha-C92 (Vulkan Compute SPIR-V Dispatch & RV64GC QEMU Execution)

## Scope
1. **`compiler/spirv_emitter.py`**: Added `emit_vulkan_compute_spirv(...)` producing Vulkan 1.2 SPIR-V 1.5 compute shaders with StorageBuffer DescriptorSet 0 Binding 0/1 (`in_buf`/`out_buf`), `GlobalInvocationId`, and `OpArrayLength` bounds check.
2. **`runtime/vulkan_runner.py`**: Pure Python `ctypes` C-ABI Vulkan 1.x compute runner (`vulkan-1.dll` / `libvulkan.so.1` / `libvulkan.1.dylib`) performing real `vkCreateInstance` -> `vkCreateDevice` -> `vkCreateComputePipelines` -> `vkCmdDispatch` with leak-free handle teardown.
3. **`compiler/riscv64_codegen.py` + `compiler/object_linker.py` + `omni_repo_compiler.py`**: Upgraded RV64 codegen from RV64IM to RV64GC (`D` float64 ops + `A` AMO/LR/SC atomics) and wired `RISCV_CALL_PLT` + `riscv64_elf` emission in `OmniRepoCompiler`.
4. **`.github/workflows/ci.yml`**: Added Ubuntu CI validation installing `spirv-tools`, `mesa-vulkan-drivers` (Lavapipe), and `qemu-user` (`qemu-riscv64`) to execute real GPU/Lavapipe Vulkan compute and RV64GC ELF64 binaries on every push.

## Verification Criteria
- `spirv-val --target-env vulkan1.2` exits 0 on generated SPIR-V compute shaders.
- `run_vulkan_compute_shader` executes bit-exact outputs on Vulkan hardware (Radeon RX 580 locally; Lavapipe ICD on Linux CI).
- `qemu-riscv64` executes RV64GC float64, `AMOADD.D`/`LR.D`+`SC.D` atomics, and multi-function `RISCV_CALL_PLT` ELF64 executables with exact return codes (`26`, `44`, `22`).
- `python -W error::ResourceWarning run_c92_tests.py`, `AetherMind_Strict_Auditor.py`, `test_empirical_audit.py`, and full unit tests pass cleanly.
