"""
Alpha-C70 Validation Suite:
1. Mach-O 64 (`x86_64` & `arm64`) Dynamic `__DATA.__got` + `LC_DYLD_INFO_ONLY` Bind Opcodes + Stub Patching + Ad-Hoc SHA-256 CodeSign.
2. `f64` Floating-Point SCCP Folding & Multi-Hop Inter-Procedural Constant Specialization + Constant-Return Propagation.
3. End-to-End `OmniRepoCompiler` Cross-Repo `f64` IP-SCCP under Heterogeneous `Homeostasis` (`llvm` + `native`) with Live Execution.
"""

import ctypes
import os
import struct
import sys
import tempfile
import unittest

from compiler.ip_sccp_gvn import InterProceduralSCCPPass, SCCPPass
from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.object_linker import NativeObjectLinker, ObjectModule
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_source_to_ssa
from omni_repo_compiler import OmniRepoCompiler
from validation.binary_structure_auditor import BinaryStructureAuditor
from validation.validator import IndependentValidator


class TestAlphaC70MachoDyldBindAndF64IpSccp(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_macho64_x86_64_and_arm64_dyld_bind_opcodes_and_got_patching(self):
        """
        Proves `build_macho64` / `emit_linked_executable` emits `__DATA.__got`,
        `LC_DYLD_INFO_ONLY` (`0x80000022`) bind opcodes for `libSystem.B.dylib`,
        patches `FF 25` (x86_64) / `ADRP+LDR+BR` (arm64) import stubs, and passes
        `BinaryStructureAuditor` including Apple Silicon `LC_CODE_SIGNATURE` SHA-256.
        """
        auditor = BinaryStructureAuditor()
        with tempfile.TemporaryDirectory() as td:
            for arch_name, triple, fmt, expected_arch in (
                ("x86_64", "x86_64-apple-macosx", "macho64", "x86-64"),
                ("arm64", "arm64-apple-macosx", "arm64_macho", "ARM64"),
            ):
                fn = SSAFunction("omni_main", ["x"])
                fn.cstrs["__c0"] = b"v=%lld\n\x00"
                bb = BasicBlock("entry")
                vx, vp, vs, vc = SSAVar("x", 0), SSAVar("p", 0), SSAVar("s", 0), SSAVar("c", 0)
                bb.add_instruction(SSAInstruction(vx, "param", ["x"]))
                bb.add_instruction(SSAInstruction(vp, "call", ["malloc", 16]))
                bb.add_instruction(SSAInstruction(vs, "cstr_addr", ["__c0"]))
                bb.add_instruction(SSAInstruction(vc, "call", ["printf", vs, vx]))
                bb.add_instruction(SSAInstruction(None, "ret", [vx]))
                fn.add_block(bb)

                llvm_be = LLVMBackend(target_triple=triple)
                obj_bytes = llvm_be.emit_object(llvm_be.compile_ir(llvm_be.ssa_module_to_llvm_ir([fn])))
                linker = NativeObjectLinker()
                linker.add_macho_object(obj_bytes, repo_name=f"mac_{arch_name}")

                out_path = linker.emit_linked_executable(
                    os.path.join(td, f"app_{arch_name}"),
                    entry_symbol="omni_main",
                    target_format=fmt,
                )
                with open(out_path, "rb") as f:
                    macho_bytes = f.read()

                rep = auditor.audit_binary(macho_bytes)
                self.assertTrue(rep.is_valid, f"Mach-O audit errors ({arch_name}): {rep.errors}")
                self.assertEqual(rep.format, "Mach-O 64")
                self.assertEqual(rep.machine_arch, expected_arch)
                self.assertIn("__DATA.__got", rep.sections)
                self.assertEqual(rep.metrics.get("dyld_bind_symbols"), ["malloc", "printf"])
                self.assertEqual(rep.metrics.get("dyld_bind_count"), 2)
                self.assertIn("/usr/lib/libSystem.B.dylib", rep.imported_symbols)
                if arch_name == "arm64":
                    self.assertTrue(rep.metrics.get("codesign_verified"))
                    # Verify patched ADRP X16 in __text (opcode 0x90000010 mask 0x9F00001F)
                    text_slice = macho_bytes[0x4000:0x8000]
                    self.assertTrue(
                        any((struct.unpack_from("<I", text_slice, off)[0] & 0x9F00001F) == 0x90000010 for off in range(0, len(text_slice) - 4, 4))
                    )
                else:
                    # Verify patched `FF 25 <disp32>` (`jmp qword ptr [rip + disp32]`) in __text
                    text_slice = macho_bytes[0x1000:0x2000]
                    self.assertIn(b"\xff\x25", text_slice)

    def test_02_f64_sccp_and_multi_hop_interprocedural_specialization(self):
        """
        Proves `SCCPPass` folds `fadd`/`fmul`/`fcmp_gt`/`sitofp` and `InterProceduralSCCPPass`
        performs multi-hop `f64` call-site specialization + pure `f64` constant-return propagation.
        """
        # Build SSA directly with explicit f64 types
        f_leaf = SSAFunction("f_leaf", ["a", "b"], param_types={"a": "f64", "b": "f64"}, return_type="f64")
        b_ent = BasicBlock("entry")
        b_then = BasicBlock("then_blk")
        b_else = BasicBlock("else_blk")
        va = SSAVar("a", 0, "f64")
        vb = SSAVar("b", 0, "f64")
        vzero = SSAVar("z", 0, "f64")
        vcmp = SSAVar("cmp", 0, "i64")
        vmul = SSAVar("m", 0, "f64")
        vadd = SSAVar("s", 0, "f64")
        vbad = SSAVar("bad", 0, "f64")
        b_ent.add_instruction(SSAInstruction(va, "param", ["a"]))
        b_ent.add_instruction(SSAInstruction(vb, "param", ["b"]))
        b_ent.add_instruction(SSAInstruction(vzero, "const", [1.0]))
        b_ent.add_instruction(SSAInstruction(vcmp, "fcmp_gt", [va, vzero]))
        b_ent.add_instruction(SSAInstruction(None, "br_cond", [vcmp, "then_blk", "else_blk"]))
        b_then.add_instruction(SSAInstruction(vmul, "fmul", [va, vb]))
        b_then.add_instruction(SSAInstruction(vadd, "fadd", [vmul, 0.5]))
        b_then.add_instruction(SSAInstruction(None, "ret", [vadd]))
        b_else.add_instruction(SSAInstruction(vbad, "fsub", [va, 99.0]))
        b_else.add_instruction(SSAInstruction(None, "ret", [vbad]))
        f_leaf.add_block(b_ent)
        f_leaf.add_block(b_then)
        f_leaf.add_block(b_else)

        f_mid = SSAFunction("f_mid", ["x", "scale"], param_types={"x": "f64", "scale": "f64"}, return_type="f64")
        bm = BasicBlock("entry")
        vx = SSAVar("x", 0, "f64")
        vsc = SSAVar("scale", 0, "f64")
        vc1 = SSAVar("c1", 0, "f64")
        vk = SSAVar("k", 0, "f64")
        vr = SSAVar("r", 0, "f64")
        bm.add_instruction(SSAInstruction(vx, "param", ["x"]))
        bm.add_instruction(SSAInstruction(vsc, "param", ["scale"]))
        bm.add_instruction(SSAInstruction(vc1, "fmul", [vsc, 2.0]))
        bm.add_instruction(SSAInstruction(vk, "call", ["f_leaf", vc1, 3.0]))
        bm.add_instruction(SSAInstruction(vr, "fadd", [vx, vk]))
        bm.add_instruction(SSAInstruction(None, "ret", [vr]))
        f_mid.add_block(bm)

        f_top = SSAFunction("f_top", ["x"], param_types={"x": "i64"}, return_type="i64")
        bt = BasicBlock("entry")
        vtx = SSAVar("x", 0, "i64")
        vtf = SSAVar("xf", 0, "f64")
        vtres = SSAVar("rf", 0, "f64")
        vtout = SSAVar("out", 0, "i64")
        bt.add_instruction(SSAInstruction(vtx, "param", ["x"]))
        bt.add_instruction(SSAInstruction(vtf, "sitofp", [vtx]))
        bt.add_instruction(SSAInstruction(vtres, "call", ["f_mid", vtf, 1.5]))
        bt.add_instruction(SSAInstruction(vtout, "fptosi", [vtres]))
        bt.add_instruction(SSAInstruction(None, "ret", [vtout]))
        f_top.add_block(bt)

        prog = {"f_leaf": f_leaf, "f_mid": f_mid, "f_top": f_top}
        opt_prog, stats = InterProceduralSCCPPass().optimize_program(prog)

        self.assertGreaterEqual(stats["specialized_functions"], 2)
        self.assertGreaterEqual(stats["ip_constant_returns_propagated"], 1)
        self.assertGreaterEqual(stats["pruned_dead_specializations"], 1)
        # `f_leaf` specialized to (3.0, 3.0) -> 3.0*3.0 + 0.5 = 9.5, propagated as `const 9.5` into `f_mid__spec_*`
        mid_specs = [k for k in opt_prog if k.startswith("f_mid__spec_")]
        self.assertEqual(len(mid_specs), 1)
        mid_spec_calls = [
            inst for blk in opt_prog[mid_specs[0]].blocks for inst in blk.instructions if inst.opcode == "call"
        ]
        self.assertEqual(len(mid_spec_calls), 0)

        # Verify via LLVM MCJIT execution: x=10 -> 10.0 + 9.5 = 19.5 -> fptosi = 19
        llvm_be = LLVMBackend()
        ir = llvm_be.ssa_module_to_llvm_ir(list(opt_prog.values()))
        mod = llvm_be.compile_ir(ir)
        cfn = llvm_be.create_jit_callable(mod, "f_top", restype=ctypes.c_int64, argtypes=[ctypes.c_int64])
        self.assertEqual(cfn(10), 19)

    def test_03_omnirepo_e2e_f64_ipsccp_heterogeneous_homeostasis(self):
        """
        Proves end-to-end `OmniRepoCompiler` cross-repository `f64` IP-SCCP specialization
        under `backend="homeostasis"` (`llvm` + `native`) with Unicorn preflight and live `ctypes.CDLL`.
        """
        r1_src = """
def scale_f64(val: float, gain: float) -> int:
    acc: float = 0.0
    if val > 0.0:
        acc = val * 3.0
    else:
        acc = val * 2.0
    if gain > 10.0:
        return int(acc + 100.0)
    elif gain > 5.0:
        return int(acc + 50.0)
    elif gain > 1.0:
        return int(acc * gain + 2.5)
    elif gain > 0.0:
        return int(acc + 1.0)
    return int(acc - 100.0)
"""
        r2_src = """
def omni_main(x: int) -> int:
    xf = float(x)
    return scale_f64(xf, 4.0)
"""
        with tempfile.TemporaryDirectory() as td:
            r1 = os.path.join(td, "repo_f64_lib")
            r2 = os.path.join(td, "repo_f64_app")
            os.makedirs(r1, exist_ok=True)
            os.makedirs(r2, exist_ok=True)

            with open(os.path.join(r1, "lib.py"), "w", encoding="utf-8") as f:
                f.write(r1_src)
            with open(os.path.join(r1, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_f64_lib"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "scale_f64", file = "lib.py", args = ["val", "gain"], return_type = "int" }]\n'
                    'imports = []\n'
                )
            with open(os.path.join(r2, "app.py"), "w", encoding="utf-8") as f:
                f.write(r2_src)
            with open(os.path.join(r2, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_f64_app"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "app.py", args = ["x"], return_type = "int" }]\n'
                    'imports = [{ name = "scale_f64", from_repo = "repo_f64_lib" }]\n'
                )

            out_lib = os.path.join(td, "c70_f64.dll" if sys.platform == "win32" else "libc70_f64.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[r1, r2],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "scale_f64": "llvm",
                        "omni_main": "native",
                    },
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            codegen = res["stages"]["codegen"]
            self.assertGreaterEqual(codegen["specialized_functions"], 1)
            self.assertGreaterEqual(codegen["sccp_folded_branches"], 1)
            # int(10 * 3 * 4.0 + 2.5) = 122, int(5 * 3 * 4.0 + 2.5) = 62
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 122)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10), 122)
            self.assertEqual(fn(5), 62)
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
