"""
Alpha-C69 Validation Suite:
1. ARM64 Data & Literal Relocations (`ARM64_PAGE21` / `ARM64_LO12`) across ELF64, Windows COFF, and macOS Mach-O + True Target-Triple LLVM Assembly.
2. Multi-OS Dynamic Mach-O 64 Executable Emission (`LC_LOAD_DYLIB`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_MAIN`, `LC_CODE_SIGNATURE`) & ARM64 ELF/PE Entry-Offset Parity.
3. Multi-Hop Transitive Inter-Procedural SCCP, Constant-Return Propagation, Dead-Specialization Pruning & Heterogeneous Homeostasis Override Inheritance.
"""

import ctypes
import os
import struct
import sys
import tempfile
import unittest

from compiler.llvm_backend import LLVMBackend
from compiler.ip_sccp_gvn import InterProceduralSCCPPass
from compiler.native_codegen import NativeCodeGenerator
from compiler.object_linker import NativeObjectLinker, ObjectModule
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_source_to_ssa
from omni_repo_compiler import OmniRepoCompiler
from validation.binary_structure_auditor import BinaryStructureAuditor
from validation.silicon_safety_sandbox import SiliconSafetySandbox
from validation.validator import IndependentValidator


class TestAlphaC69Arm64RodataMachoExecAndTransitiveIpSccp(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_arm64_page21_lo12_rodata_relocations_across_elf_coff_and_macho(self):
        """
        Proves ARM64 `ADRP` (`ARM64_PAGE21`) and `ADD`/`LDR` (`ARM64_LO12`) relocations
        for `.rodata` lookup tables and C-strings across Linux ELF64, Windows COFF, and
        macOS Mach-O 64 object files, executing in Unicorn ARM64.
        """
        fn = SSAFunction("arm_lut_cstr_kernel", ["idx"])
        fn.cstrs["__cstr_0"] = b"item=%lld\n\x00"
        fn.luts["__lut_0"] = ("i64", [100, 200, 300, 400])
        bb = BasicBlock("entry")
        v_idx = SSAVar("idx", 0)
        v_str = SSAVar("s", 0)
        v_lut = SSAVar("l", 0)
        v_call = SSAVar("c", 0)
        v_out = SSAVar("out", 0)
        bb.add_instruction(SSAInstruction(v_idx, "param", ["idx"]))
        bb.add_instruction(SSAInstruction(v_str, "cstr_addr", ["__cstr_0"]))
        bb.add_instruction(SSAInstruction(v_lut, "lut_load", ["__lut_0", "i64", v_idx]))
        bb.add_instruction(SSAInstruction(v_call, "call", ["printf", v_str, v_lut]))
        bb.add_instruction(SSAInstruction(v_out, "add", [v_lut, 7]))
        bb.add_instruction(SSAInstruction(None, "ret", [v_out]))
        fn.add_block(bb)

        caller_src = """
def arm_entry(i: int) -> int:
    return arm_lut_cstr_kernel(i) + 1000
"""
        caller_ssa = lower_source_to_ssa(caller_src, "arm_entry", optimize=False)
        arm_cg = NativeCodeGenerator(arch="arm64", target_os="linux")
        caller_art = arm_cg.compile_ssa(caller_ssa)

        sandbox = SiliconSafetySandbox()
        targets = [
            ("aarch64-unknown-linux-gnu", "add_elf_object", ".cfi_startproc"),
            ("aarch64-pc-windows-msvc", "add_coff_object", ".seh_proc"),
            ("arm64-apple-macosx", "add_macho_object", "__TEXT,__text"),
        ]

        for triple, loader_method, expected_asm_marker in targets:
            llvm_be = LLVMBackend(target_triple=triple)
            self.assertTrue(llvm_be.is_available)
            ir = llvm_be.ssa_module_to_llvm_ir([fn])
            mod = llvm_be.compile_ir(ir)
            asm_txt = llvm_be.emit_assembly(mod)
            self.assertIn(expected_asm_marker, asm_txt)

            obj_bytes = llvm_be.emit_object(mod)
            linker = NativeObjectLinker()

            # Add caller module first so arm_lut_cstr_kernel is placed at a non-zero offset
            caller_mod = ObjectModule("caller_arm64")
            caller_mod.add_symbol("arm_entry", caller_art.code_bytes, is_exported=True)
            for rel in caller_art.relocations:
                caller_mod.add_call_relocation(rel.offset, rel.symbol_name, rel.reloc_type, rel.addend)
            linker.add_module(caller_mod)

            getattr(linker, loader_method)(obj_bytes, repo_name=f"llvm_{triple}")
            link_res = linker.link(entry_symbol="arm_entry")
            self.assertTrue(link_res["success"])
            # 1 ARM64_CALL26 in caller + 2 ARM64_PAGE21 + 2 ARM64_LO12 + 1 ARM64_CALL26 in kernel = 6
            self.assertGreaterEqual(link_res["relocations_applied"], 6)

            entry_off = link_res["global_symbols"]["arm_entry"]
            for idx_arg, expected_val in ((0, 1107), (1, 1207), (2, 1307), (3, 1407)):
                sim = sandbox.emulate_arm64(
                    link_res["combined_code"],
                    args=[idx_arg],
                    start_offset=entry_off,
                )
                self.assertTrue(sim.is_safe_for_silicon, f"Unicorn ARM64 fault for {triple}: {sim}")
                self.assertEqual(sim.return_value, expected_val, f"Mismatch for {triple} idx={idx_arg}")

    def test_02_dynamic_macho_executable_and_arm64_entry_offset_audit(self):
        """
        Proves dynamic Mach-O 64 (`macho64` & `arm64_macho`) executable emission with
        `LC_LOAD_DYLIB` (`/usr/lib/libSystem.B.dylib`), `LC_SYMTAB`, `LC_DYSYMTAB`,
        `LC_MAIN` entry offset, and ARM64 ELF/PE entry-offset propagation.
        """
        auditor = BinaryStructureAuditor()

        with tempfile.TemporaryDirectory() as td:
            # 1. Build a 2-module ARM64 program where `omni_main` is at non-zero offset and imports `printf` + `malloc`
            helper_arm = NativeCodeGenerator(arch="arm64", target_os="macos").compile_ssa(
                lower_source_to_ssa("def helper_pad(x: int) -> int:\n    return x * 3 + 1\n", "helper_pad", optimize=False)
            )
            main_fn = SSAFunction("omni_main", ["x"])
            main_fn.cstrs["__c0"] = b"hi=%lld\n\x00"
            bb = BasicBlock("entry")
            vx = SSAVar("x", 0)
            vp = SSAVar("p", 0)
            vs = SSAVar("s", 0)
            vc = SSAVar("c", 0)
            vh = SSAVar("h", 0)
            bb.add_instruction(SSAInstruction(vx, "param", ["x"]))
            bb.add_instruction(SSAInstruction(vp, "call", ["malloc", 32]))
            bb.add_instruction(SSAInstruction(vs, "cstr_addr", ["__c0"]))
            bb.add_instruction(SSAInstruction(vc, "call", ["printf", vs, vx]))
            bb.add_instruction(SSAInstruction(vh, "call", ["helper_pad", vx]))
            bb.add_instruction(SSAInstruction(None, "ret", [vh]))
            main_fn.add_block(bb)

            llvm_mac_arm = LLVMBackend(target_triple="arm64-apple-macosx")
            mac_arm_obj = llvm_mac_arm.emit_object(llvm_mac_arm.compile_ir(llvm_mac_arm.ssa_module_to_llvm_ir([main_fn])))

            linker = NativeObjectLinker()
            m_help = ObjectModule("mod_helper")
            m_help.add_symbol("helper_pad", helper_arm.code_bytes, is_exported=True)
            linker.add_module(m_help)
            linker.add_macho_object(mac_arm_obj, repo_name="mod_main")

            link_res = linker.link(entry_symbol="omni_main")
            entry_off = link_res["global_symbols"]["omni_main"]
            self.assertGreater(entry_off, 0)
            self.assertIn("printf", link_res["external_os_imports"])
            self.assertIn("malloc", link_res["external_os_imports"])

            # Emit arm64_macho executable
            macho_arm_path = linker.emit_linked_executable(
                os.path.join(td, "app_arm64_macos"),
                entry_symbol="omni_main",
                target_format="arm64_macho",
            )
            with open(macho_arm_path, "rb") as f:
                macho_arm_bytes = f.read()
            rep_macho_arm = auditor.audit_binary(macho_arm_bytes)
            self.assertTrue(rep_macho_arm.is_valid, f"Audit errors: {rep_macho_arm.errors}")
            self.assertEqual(rep_macho_arm.format, "Mach-O 64")
            self.assertEqual(rep_macho_arm.machine_arch, "ARM64")
            self.assertEqual(rep_macho_arm.binary_type, "executable")
            self.assertIn("omni_main", rep_macho_arm.exported_symbols)
            self.assertIn("helper_pad", rep_macho_arm.exported_symbols)
            self.assertIn("/usr/lib/libSystem.B.dylib", rep_macho_arm.imported_symbols)
            self.assertIn("printf", rep_macho_arm.imported_symbols)
            self.assertIn("malloc", rep_macho_arm.imported_symbols)
            self.assertTrue(rep_macho_arm.metrics.get("dysymtab_present"))
            self.assertTrue(rep_macho_arm.metrics.get("codesign_verified"))
            self.assertEqual(rep_macho_arm.metrics.get("entry_offset"), 0x4000 + entry_off)

            # Emit standalone arm64_pe executable and verify AddressOfEntryPoint reflects entry_offset
            pe_arm_path = linker.emitter.emit_standalone_binary(
                os.path.join(td, "app_arm64_win.exe"),
                target_format="arm64_pe",
                custom_code=link_res["combined_code"],
                entry_offset=entry_off,
            )
            with open(pe_arm_path, "rb") as f:
                pe_arm_bytes = f.read()
            rep_pe_arm = auditor.audit_binary(pe_arm_bytes)
            self.assertTrue(rep_pe_arm.is_valid)
            self.assertEqual(rep_pe_arm.machine_arch, "ARM64")
            self.assertEqual(rep_pe_arm.metrics["entry_point_rva"], hex(0x1000 + entry_off))

            # Emit standalone arm64_elf executable and verify BL instruction targets 12 + entry_offset
            elf_arm_path = linker.emitter.emit_standalone_binary(
                os.path.join(td, "app_arm64_linux"),
                target_format="arm64_elf",
                custom_code=link_res["combined_code"],
                entry_offset=entry_off,
            )
            with open(elf_arm_path, "rb") as f:
                elf_arm_bytes = f.read()
            rep_elf_arm = auditor.audit_binary(elf_arm_bytes)
            self.assertTrue(rep_elf_arm.is_valid)
            self.assertEqual(rep_elf_arm.machine_arch, "ARM64")
            bl_word = struct.unpack_from("<I", elf_arm_bytes, 120)[0]
            self.assertEqual(bl_word & 0xFC000000, 0x94000000)
            self.assertEqual((bl_word & 0x03FFFFFF) * 4, 12 + entry_off)

    def test_03_multi_hop_transitive_ipsccp_and_heterogeneous_homeostasis_inheritance(self):
        """
        Proves multi-hop transitive Inter-Procedural SCCP specialization (`tier1 -> tier2`),
        pure constant-return propagation, dead specialization pruning, and automatic
        inheritance of `homeostasis_function_overrides` by specialized `__spec_` clones.
        """
        tier2_src = """
def tier2(a: int, b: int) -> int:
    if a > 10:
        return a * b + 7
    else:
        return a - 999
"""
        tier1_src = """
def tier1(x: int, factor: int) -> int:
    c = factor * 3
    k = tier2(c, 5)
    if k == 67:
        return x * 20 + k
    else:
        return x - 500
"""
        main_src = """
def omni_main(x: int) -> int:
    return tier1(x, 4)
"""
        prog = {
            "tier2": lower_source_to_ssa(tier2_src, "tier2", optimize=True),
            "tier1": lower_source_to_ssa(tier1_src, "tier1", optimize=True),
            "omni_main": lower_source_to_ssa(main_src, "omni_main", optimize=True),
        }
        opt_prog, stats = InterProceduralSCCPPass().optimize_program(prog)
        self.assertGreaterEqual(stats["specialized_functions"], 2)
        self.assertGreaterEqual(stats["ip_constant_returns_propagated"], 1)
        self.assertGreaterEqual(stats["pruned_dead_specializations"], 1)

        # `tier2__spec_a1_5__spec_a0_12` was folded into `const 67` inside `tier1__spec_a1_4` and then pruned!
        self.assertNotIn("tier2__spec_a1_5__spec_a0_12", opt_prog)
        tier1_specs = [k for k in opt_prog if k.startswith("tier1__spec_")]
        self.assertEqual(len(tier1_specs), 1)
        tier1_spec_calls = [
            inst
            for b in opt_prog[tier1_specs[0]].blocks
            for inst in b.instructions
            if inst.opcode == "call"
        ]
        self.assertEqual(len(tier1_spec_calls), 0)

        # Now verify end-to-end OmniRepoCompiler heterogeneous Homeostasis compilation
        # where `tier1` is assigned to `llvm` and `omni_main` is assigned to `native`
        with tempfile.TemporaryDirectory() as td:
            r1 = os.path.join(td, "repo_tiers")
            r2 = os.path.join(td, "repo_main")
            os.makedirs(r1, exist_ok=True)
            os.makedirs(r2, exist_ok=True)

            with open(os.path.join(r1, "tiers.py"), "w", encoding="utf-8") as f:
                f.write(tier2_src + "\n" + tier1_src)
            with open(os.path.join(r1, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_tiers"\n'
                    'version = "1.0.0"\n'
                    'exports = [\n'
                    '  { name = "tier2", file = "tiers.py", args = ["a", "b"], return_type = "int" },\n'
                    '  { name = "tier1", file = "tiers.py", args = ["x", "factor"], return_type = "int" }\n'
                    ']\n'
                    'imports = []\n'
                )

            with open(os.path.join(r2, "main.py"), "w", encoding="utf-8") as f:
                f.write(main_src)
            with open(os.path.join(r2, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_main"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "main.py", args = ["x"], return_type = "int" }]\n'
                    'imports = [{ name = "tier1", from_repo = "repo_tiers" }]\n'
                )

            out_lib = os.path.join(td, "c69_hybrid.dll" if sys.platform == "win32" else "libc69_hybrid.so")
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
                        "tier1": "llvm",
                        "omni_main": "native",
                    },
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            homeo = res["stages"]["homeostasis"]
            fn_emitters = homeo["function_emitters"]
            spec_tier1_keys = [k for k in fn_emitters if k.startswith("tier1__spec_")]
            self.assertTrue(
                fn_emitters.get("tier1") == "llvm" or any(fn_emitters[k] == "llvm" for k in spec_tier1_keys),
                f"Expected tier1 or tier1__spec_* to inherit llvm override, got {fn_emitters}",
            )
            self.assertEqual(fn_emitters.get("omni_main"), "native")
            self.assertTrue(homeo["heterogeneous_link"])
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 267)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            val = fn(10)
            self.assertEqual(val, 267)
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
