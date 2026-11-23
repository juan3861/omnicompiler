"""
Alpha-C92 Verification Suite:
1. Binary Khronos SPIR-V 1.5 SSBO Compute Shader emission (`emit_vulkan_compute_spirv`)
   validated with Khronos `spirv-val` and executed via real Vulkan C-ABI (`runtime/vulkan_runner.py`).
2. RISC-V 64 RV64GC (IMAFDC + A Atomics) machine code generation (`compiler/riscv64_codegen.py`),
   cross-function `RISCV_CALL_PLT` ELF64 linking, and native `qemu-riscv64` execution.
"""

import ast
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.riscv64_codegen import Riscv64CodeGenerator
from compiler.spirv_emitter import SPIRVEmitter, validate_spirv_binary
from compiler.ssa_ir import AstToSsaLowering, BasicBlock, SSAFunction, SSAInstruction, SSAVar
from omni_repo_compiler import OmniRepoCompiler
from runtime.vulkan_runner import is_vulkan_device_available, run_vulkan_compute_shader


def _find_spirv_val() -> str:
    p = shutil.which("spirv-val") or shutil.which("spirv-val.EXE")
    if p:
        return p
    win_cand = r"C:\VulkanSDK\1.4.341.1\Bin\spirv-val.EXE"
    if os.path.exists(win_cand):
        return win_cand
    vk_sdk = os.environ.get("VULKAN_SDK")
    if vk_sdk:
        for nm in ("spirv-val.EXE", "spirv-val"):
            cp = os.path.join(vk_sdk, "Bin", nm)
            if os.path.exists(cp):
                return cp
    return ""


class TestAlphaC92VulkanAndRv64gc(unittest.TestCase):
    def test_01_vulkan_compute_spirv_and_hardware_or_lavapipe_dispatch(self):
        src = "def gpu_mix(x: int) -> int:\n    return (x * 3 + 7) ^ 0x5A\n"
        fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        spv = SPIRVEmitter().emit_vulkan_compute_spirv(fn, workgroup_size=(64, 1, 1))

        val_rep = validate_spirv_binary(spv)
        self.assertTrue(val_rep["valid"], val_rep)

        spv_val = _find_spirv_val()
        if os.environ.get("SPIRV_VAL_REQUIRE") == "1":
            self.assertTrue(bool(spv_val), "spirv-val required in CI environment")
        if spv_val:
            with tempfile.TemporaryDirectory() as td:
                spv_path = os.path.join(td, "gpu_mix.spv")
                with open(spv_path, "wb") as f:
                    f.write(spv)
                proc = subprocess.run(
                    [spv_val, "--target-env", "vulkan1.2", spv_path],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, f"spirv-val failed: {proc.stderr}")

        probe = is_vulkan_device_available()
        if os.environ.get("VK_REQUIRE_RUNTIME") == "1":
            self.assertTrue(probe.get("available"), f"Vulkan device required in CI: {probe}")
        if probe.get("available"):
            xs = [0, 1, 2, 7, 13, 42, -5, 1024]
            res = run_vulkan_compute_shader(spv, xs, local_size_x=64)
            self.assertTrue(res["executed"])
            expected = [((x * 3 + 7) ^ 0x5A) for x in xs]
            self.assertEqual(res["outputs"], expected)

    def test_02_rv64gc_float_and_atomic_instruction_emission(self):
        # 1. Float64 SSA kernel: int 7 -> f64 * 3.5 + 1.5 -> int 26
        fn_f = SSAFunction("rv_fp_test", [])
        bb_f = BasicBlock("entry")
        v7 = SSAVar("v7", 0)
        f7 = SSAVar("f7", 0, "f64")
        fm = SSAVar("fm", 0, "f64")
        fa = SSAVar("fa", 0, "f64")
        res_i = SSAVar("res_i", 0)
        bb_f.instructions = [
            SSAInstruction(v7, "const", [7]),
            SSAInstruction(f7, "sitofp", [v7]),
            SSAInstruction(fm, "fmul", [f7, 3.5]),
            SSAInstruction(fa, "fadd", [fm, 1.5]),
            SSAInstruction(res_i, "fptosi", [fa]),
            SSAInstruction(None, "ret", [res_i]),
        ]
        fn_f.blocks = [bb_f]
        fn_f.entry_block = bb_f

        # 2. RV64A Atomics kernel: alloca(8) = 10 -> atomic_add(+5) -> cas(15->42) -> cas(99->77 fail) -> load == 42
        fn_a = SSAFunction("rv_amo_test", [])
        bb_a = BasicBlock("entry")
        ptr = SSAVar("ptr", 0)
        c10 = SSAVar("c10", 0)
        c5 = SSAVar("c5", 0)
        c15 = SSAVar("c15", 0)
        c42 = SSAVar("c42", 0)
        c99 = SSAVar("c99", 0)
        c77 = SSAVar("c77", 0)
        old1 = SSAVar("old1", 0)
        old2 = SSAVar("old2", 0)
        old3 = SSAVar("old3", 0)
        cur = SSAVar("cur", 0)
        ok = SSAVar("ok", 0)
        bad = SSAVar("bad", 0)
        s1 = SSAVar("s1", 0)
        s2 = SSAVar("s2", 0)
        bb_a.instructions = [
            SSAInstruction(ptr, "alloca", [8]),
            SSAInstruction(c10, "const", [10]),
            SSAInstruction(c5, "const", [5]),
            SSAInstruction(c15, "const", [15]),
            SSAInstruction(c42, "const", [42]),
            SSAInstruction(c99, "const", [99]),
            SSAInstruction(c77, "const", [77]),
            SSAInstruction(None, "store", [ptr, c10]),
            SSAInstruction(old1, "atomic_add", [ptr, c5]),
            SSAInstruction(old2, "atomic_cas", [ptr, c15, c42]),
            SSAInstruction(old3, "atomic_cas", [ptr, c99, c77]),
            SSAInstruction(None, "fence", []),
            SSAInstruction(cur, "load", [ptr]),
            SSAInstruction(ok, "cmp_eq", [old2, c15]),
            SSAInstruction(bad, "cmp_eq", [old3, c42]),
            SSAInstruction(s1, "add", [cur, ok]),
            SSAInstruction(s2, "add", [s1, bad]),
            SSAInstruction(None, "ret", [s2]),  # 42 + 1 + 1 = 44
        ]
        fn_a.blocks = [bb_a]
        fn_a.entry_block = bb_a

        cg = Riscv64CodeGenerator()
        art_f = cg.compile_function(fn_f)
        art_a = cg.compile_function(fn_a)
        self.assertGreater(len(art_f.code_bytes), 20)
        self.assertEqual(len(art_f.code_bytes) % 4, 0)
        self.assertGreater(len(art_a.code_bytes), 40)
        self.assertEqual(len(art_a.code_bytes) % 4, 0)

        # Verify RISC-V ELF64 header (e_machine = 0xF3)
        elf_f = StandaloneBinaryEmitter().build_riscv64_elf(custom_code=art_f.code_bytes, entry_offset=0)
        elf_a = StandaloneBinaryEmitter().build_riscv64_elf(custom_code=art_a.code_bytes, entry_offset=0)
        self.assertEqual(elf_f[:4], b"\x7fELF")
        self.assertEqual(struct.unpack_from("<H", elf_f, 18)[0], 0xF3)

        qemu = shutil.which("qemu-riscv64")
        if os.environ.get("QEMU_RISCV64_REQUIRE") == "1":
            self.assertTrue(bool(qemu), "qemu-riscv64 required in CI environment")
        if qemu:
            with tempfile.TemporaryDirectory() as td:
                pf = os.path.join(td, "rv_fp")
                pa = os.path.join(td, "rv_amo")
                with open(pf, "wb") as f:
                    f.write(elf_f)
                with open(pa, "wb") as f:
                    f.write(elf_a)
                os.chmod(pf, 0o755)
                os.chmod(pa, 0o755)
                self.assertEqual(subprocess.run([qemu, pf]).returncode, 26)
                self.assertEqual(subprocess.run([qemu, pa]).returncode, 44)

    def test_03_omni_compiler_e2e_riscv64_elf_cross_module_call(self):
        with tempfile.TemporaryDirectory() as td:
            src_path = os.path.join(td, "app.py")
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(
                    "def helper_rv(n: int) -> int:\n"
                    "    return n * 3 + 7\n\n"
                    "def main_rv() -> int:\n"
                    "    return helper_rv(5)\n"
                )
            out_bin = os.path.join(td, "app_rv64")
            comp = OmniRepoCompiler()
            res = comp.compile_repositories(
                [td],
                output_path=out_bin,
                target_format="executable",
                target_os="linux",
                target_arch="riscv64",
                entry_export="main_rv",
                export_all=True,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["stages"]["emission"]["resolved_binary_format"], "riscv64_elf")
            self.assertEqual(res["stages"]["formal_audit"]["machine_arch"], "RISC-V 64")

            qemu = shutil.which("qemu-riscv64")
            if qemu:
                os.chmod(res["stages"]["emission"]["artifact_path"], 0o755)
                rc = subprocess.run([qemu, res["stages"]["emission"]["artifact_path"]]).returncode
                self.assertEqual(rc, 22)


if __name__ == "__main__":
    unittest.main()
