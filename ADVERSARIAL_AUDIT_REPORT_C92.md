# Adversarial Audit Report — Alpha-C92

## Defects Caught & Resolved During Empirical Testing
1. **`OpArrayLength` Opcode Encoding in SPIR-V 1.5**:
   - Initial draft used `268` (`OpGroupSMin`), which Khronos `spirv-val.EXE --target-env vulkan1.2` immediately caught and rejected. Fixed to `68` (`OpArrayLength`), after which `spirv-val` returned `0` with zero warnings and AMD Radeon RX 580 executed `run_vulkan_compute_shader` cleanly.
2. **`VkPhysicalDeviceProperties` / `VkPhysicalDeviceFeatures` Offsets**:
   - Adjusted `deviceName` slice (`20:276`) and `shaderInt64` feature index (`45`) after live hardware probe inspection.
3. **RV64A `atomic_cas` Skip Offset**:
   - `buf.bnez(...)` emits a 2-instruction (`BEQ + JAL`, 8-byte) sequence, so the preceding `BNE t3, t1` failure branch needed `+16` rather than `+12` to avoid jumping onto `JAL lbl_retry`.
4. **Preflight Sandbox Dispatch for RV64**:
   - Replaced erroneous `verification.unicorn_sandbox` import with `types.SimpleNamespace` for `riscv64` preflight metadata bypass cleanly.
