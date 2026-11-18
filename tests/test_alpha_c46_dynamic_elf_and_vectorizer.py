"""
Alpha-C46 Verification Test Suite:
1. Linux dynamic ELF64 binary emission (PT_INTERP, PT_DYNAMIC, DT_NEEDED, DT_BIND_NOW, GOT/PLT).
2. Two-pass length-stable callable custom_code GOT resolution.
3. Live OS execution of dynamic ELF (calling libc.so.6!abs(-137) -> 137) via WSL/Linux.
4. Unified StandaloneBinaryEmitter.emit_dynamic_executable API (PE multi-import & ELF).
5. LoopVectorizerPass auto-vectorization of C-ABI struct array reduction loops (META-P2-VECTORIZER).
6. Multi-backend execution parity: Native W^X JIT and LLVM O3 JIT on vectorized struct reductions.
"""

import ast
import ctypes
import os
import shutil
import struct
import subprocess
import sys
import unittest
from typing import Dict, Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.llvm_backend import LLVMBackend
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering, optimize_ssa
from validation.binary_structure_auditor import BinaryStructureAuditor


class TestAlphaC46DynamicElfAndVectorizer(unittest.TestCase):
    def setUp(self):
        self.emitter = StandaloneBinaryEmitter()
        self.auditor = BinaryStructureAuditor()
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c46_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_01_dynamic_elf_emission_and_structure(self):
        """Verifies dynamic ELF64 binary structure with PT_INTERP, PT_DYNAMIC, and DT_NEEDED."""
        elf_bytes, got_slots = self.emitter.build_elf64_dynamic_exe(
            needed_libs=["libc.so.6"],
            imported_funcs=["abs", "exit"],
            exit_code=42,
        )
        self.assertGreater(len(elf_bytes), 256)
        self.assertIn("abs", got_slots)
        self.assertIn("exit", got_slots)
        self.assertGreater(got_slots["abs"], self.emitter.VADDR_ELF)

        report = self.auditor.audit_binary(elf_bytes)
        self.assertTrue(report.is_valid)
        self.assertEqual(report.format, "ELF64")
        self.assertEqual(report.machine_arch, "x86-64")

    def test_02_dynamic_elf_callable_custom_code_two_pass(self):
        """Verifies two-pass length-stable callable custom_code with RIP-relative GOT slot dereference."""
        def code_builder(slots: Dict[str, int], entry_vaddr: int) -> bytes:
            abs_slot = slots["abs"]
            code = bytearray()
            # mov edi, -42 (0xFFFFFFD6)
            code.extend(b"\xbf\xd6\xff\xff\xff")
            # mov rax, [rip + disp32] (dereference abs GOT slot)
            code.extend(b"\x48\x8b\x05")
            disp = abs_slot - (entry_vaddr + len(code) + 4)
            code.extend(struct.pack("<i", disp))
            # call rax
            code.extend(b"\xff\xd0")
            # mov edi, eax
            code.extend(b"\x89\xc7")
            # mov eax, 60 (sys_exit)
            code.extend(b"\xb8\x3c\x00\x00\x00")
            # syscall
            code.extend(b"\x0f\x05")
            return bytes(code)

        elf_bytes, got_slots = self.emitter.build_elf64_dynamic_exe(
            needed_libs=["libc.so.6"],
            imported_funcs=["abs"],
            custom_code=code_builder,
        )
        self.assertGreater(len(elf_bytes), 300)
        self.assertIn("abs", got_slots)

        report = self.auditor.audit_binary(elf_bytes)
        self.assertTrue(report.is_valid)
        self.assertEqual(report.format, "ELF64")
        self.assertEqual(report.machine_arch, "x86-64")

    def test_03_live_linux_execution_via_wsl_or_subprocess(self):
        """Executes emitted dynamic ELF calling libc.so.6!abs(-137) and checks exit code 137."""
        def code_builder(slots: Dict[str, int], entry_vaddr: int) -> bytes:
            abs_slot = slots["abs"]
            code = bytearray()
            # mov edi, -137 (0xFFFFFF77)
            code.extend(b"\xbf" + struct.pack("<i", -137))
            # mov rax, [rip + disp32]
            code.extend(b"\x48\x8b\x05")
            disp = abs_slot - (entry_vaddr + len(code) + 4)
            code.extend(struct.pack("<i", disp))
            # call rax -> returns 137 in eax
            code.extend(b"\xff\xd0")
            # mov edi, eax
            code.extend(b"\x89\xc7")
            # mov eax, 60 (sys_exit)
            code.extend(b"\xb8\x3c\x00\x00\x00")
            # syscall
            code.extend(b"\x0f\x05")
            return bytes(code)

        elf_bytes, _ = self.emitter.build_elf64_dynamic_exe(
            needed_libs=["libc.so.6"],
            imported_funcs=["abs"],
            custom_code=code_builder,
        )
        elf_path = os.path.join(self.test_dir, "test_elf_live")
        with open(elf_path, "wb") as f:
            f.write(elf_bytes)

        if sys.platform != "win32":
            os.chmod(elf_path, 0o755)
            proc = subprocess.run([elf_path], capture_output=True)
            self.assertEqual(proc.returncode, 137)
        else:
            wsl_check = subprocess.run(["wsl", "uname"], capture_output=True, text=True)
            if wsl_check.returncode == 0 and "Linux" in wsl_check.stdout:
                wsl_posix_path = elf_path.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"chmod +x {wsl_posix_path} && {wsl_posix_path}"
                proc = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True)
                self.assertEqual(proc.returncode, 137)

    def test_04_emit_dynamic_executable_unified_api(self):
        """Verifies StandaloneBinaryEmitter.emit_dynamic_executable unified API across platforms."""
        # 1. Test PE multi-import on Windows format
        pe_path = os.path.join(self.test_dir, "test_dynamic.exe")
        out_path, pe_slots = self.emitter.emit_dynamic_executable(
            output_path=pe_path,
            needed_libs={"KERNEL32.dll": ["ExitProcess"], "MSVCRT.dll": ["abs"]},
            target_format="pe64",
            exit_code=17,
        )
        self.assertTrue(os.path.exists(out_path))
        self.assertIn("ExitProcess", pe_slots)
        self.assertIn("abs", pe_slots)
        with open(out_path, "rb") as bf:
            pe_audit = self.auditor.audit_binary(bf.read())
        self.assertTrue(pe_audit.is_valid)
        self.assertEqual(pe_audit.format, "PE32+")

        # 2. Test ELF dynamic executable
        elf_path = os.path.join(self.test_dir, "test_dynamic_elf")
        out_elf, elf_slots = self.emitter.emit_dynamic_executable(
            output_path=elf_path,
            needed_libs=["libc.so.6"],
            imported_funcs=["abs", "exit"],
            target_format="elf64",
            exit_code=23,
        )
        self.assertTrue(os.path.exists(out_elf))
        self.assertIn("abs", elf_slots)
        with open(out_elf, "rb") as bf:
            elf_audit = self.auditor.audit_binary(bf.read())
        self.assertTrue(elf_audit.is_valid)
        self.assertEqual(elf_audit.format, "ELF64")

    def test_05_struct_array_loop_vectorization(self):
        """Verifies LoopVectorizerPass detects and vectorizes C-ABI struct array reduction loops into SIMD trees."""
        src = """
class HeavyPacket:
    flags: u32
    weights: Array[f32, 4]

def compute_packet_weight(pkt: HeavyPacket) -> float:
    acc = 0.0
    i = 0
    while i < 4:
        acc += pkt.weights[i]
        i += 1
    return acc
"""
        mod = ast.parse(src)
        lowering = AstToSsaLowering()
        lowering.register_structs_from_statements(mod.body)
        fn_ast = [n for n in mod.body if isinstance(n, ast.FunctionDef)][0]
        ssa_fn = lowering.lower_function_def(fn_ast)

        pass_vec = LoopVectorizerPass()
        opt_fn, stats = pass_vec.vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        # Confirm while loop was replaced by tree reduction loads
        opcodes = [inst.opcode for b in opt_fn.blocks for inst in b.instructions]
        self.assertNotIn("cmp_lt", opcodes)
        self.assertNotIn("br_cond", opcodes)
        self.assertEqual(opcodes.count("load_off"), 4)
        self.assertEqual(opcodes.count("fadd"), 3)

    def test_06_vectorized_struct_array_execution_parity_native_llvm(self):
        """Verifies execution parity between Native W^X JIT and LLVM O3 on vectorized struct reduction."""
        src = """
class SignalBuffer:
    channel: u32
    samples: Array[f32, 4]

def sum_samples(buf: SignalBuffer) -> float:
    total = 0.0
    idx = 0
    while idx < 4:
        total += buf.samples[idx]
        idx += 1
    return total
"""
        mod = ast.parse(src)
        lowering = AstToSsaLowering()
        lowering.register_structs_from_statements(mod.body)
        fn_ast = [n for n in mod.body if isinstance(n, ast.FunctionDef)][0]
        ssa_fn = lowering.lower_function_def(fn_ast)

        pass_vec = LoopVectorizerPass()
        ssa_fn, stats = pass_vec.vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)
        ssa_fn = optimize_ssa(ssa_fn)

        class SignalBufferStruct(ctypes.Structure):
            _fields_ = [
                ("channel", ctypes.c_uint32),
                ("samples", ctypes.c_float * 4),
            ]

        test_buf = SignalBufferStruct()
        test_buf.channel = 7
        test_buf.samples[0] = 10.25
        test_buf.samples[1] = 20.50
        test_buf.samples[2] = 30.75
        test_buf.samples[3] = 40.50
        expected = 10.25 + 20.50 + 30.75 + 40.50  # 102.0
        buf_ptr = ctypes.addressof(test_buf)

        # 1. Native W^X JIT execution
        native_jit = NativeJitCompiler()
        cfunc, mem, _ = native_jit.compile_ssa(ssa_fn)
        native_res = cfunc(buf_ptr)
        self.assertAlmostEqual(native_res, expected, places=4)

        # 2. LLVM O3 JIT execution
        llvm_be = LLVMBackend(opt_level=3)
        llvm_ir = llvm_be.ssa_to_llvm_ir(ssa_fn)
        compiled_mod = llvm_be.compile_ir(llvm_ir)
        jit_fn = llvm_be.create_jit_callable(
            compiled_mod,
            "sum_samples",
            restype=ctypes.c_double,
            argtypes=[ctypes.c_void_p],
        )
        llvm_res = jit_fn(buf_ptr)
        self.assertAlmostEqual(llvm_res, expected, places=4)
        self.assertAlmostEqual(native_res, llvm_res, places=5)


if __name__ == "__main__":
    unittest.main()
