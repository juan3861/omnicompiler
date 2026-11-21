"""
Alpha-C68 Verification Suite:
1. WebAssembly Explicit Address-Ordered Coalescing Free-List Heap (`malloc`, `free`, `calloc`, `realloc`)
   proving forward/backward coalescing, block splitting, double-free immunity, and top-of-heap reclaim.
2. Mach-O 64-bit (`x86_64-apple-macosx` & `arm64-apple-macosx`) `load_macho_object` ingestion,
   cross-module `REL32` / `ARM64_CALL26` relocation patching, `OmniRepoCompiler` hybrid macOS builds,
   and physical execution in Unicorn x86-64 & Unicorn AArch64 sandboxes.
3. 4-Language Real Polyglot Homeostasis (`C` + `Rust` + `TypeScript` + `Go`) compiled and heterogeneously
   linked across Omni Native, LLVM 20 `-O3`, and GCC `-O3` into unified native `.dll`/`.so` & ELF64 binaries
   with DWARF v5 `.debug_line` coverage.
"""

import ast
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from compiler.gcc_backend import GCCBackend
from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.object_linker import NativeObjectLinker, ObjectModule, load_macho_object
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.silicon_safety_sandbox import SiliconSafetySandbox


def _unload_cdll(lib: Any) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if sys.platform == "win32" and handle:
        import _ctypes
        _ctypes.FreeLibrary(handle)


class TestAlphaC68WasmCoalescingMachoAndPolyglotHybrid(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="omni_alpha_c68_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_wasm_coalescing_freelist_allocator_merge_split_reclaim(self):
        """Verifies WASM heap coalescing, block splitting, double-free safety, realloc & top reclaim."""
        fn = SSAFunction("wasm_freelist_e2e", [], return_type="i64")
        b = BasicBlock("entry")
        (
            p1, p2, p3, p4, p5, p6, p7, p8, p9,
            diff76, v4, v9, eq_coalesce, eq_reclaim, eq_split_ok,
            ge_split_diff, s1, s2, s3, ans
        ) = [
            SSAVar(n, 0, "i64")
            for n in (
                "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9",
                "diff76", "v4", "v9", "eq_coalesce", "eq_reclaim", "eq_split_ok",
                "ge_split_diff", "s1", "s2", "s3", "ans",
            )
        ]
        b.instructions = [
            # 1. Forward + backward coalescing of non-LIFO frees
            SSAInstruction(p1, "call", ["malloc", 64]),
            SSAInstruction(p2, "call", ["malloc", 64]),
            SSAInstruction(p3, "call", ["malloc", 64]),
            SSAInstruction(None, "call", ["free", p1]),
            SSAInstruction(None, "call", ["free", p2]),      # Merges p1+p2 (144B free block)
            SSAInstruction(p4, "call", ["malloc", 128]),     # Must reuse p1
            SSAInstruction(None, "store_off", [p4, 0, 777, "i64"]),
            SSAInstruction(p9, "call", ["realloc", p4, 144]),
            SSAInstruction(v9, "load_off", [p9, 0, "i64"]),
            SSAInstruction(None, "call", ["free", p2]),      # Double free ignored cleanly
            SSAInstruction(None, "call", ["free", 0]),       # NULL free ignored cleanly
            # 2. Top-of-heap tail reclaim resets $__omni_heap_ptr
            SSAInstruction(None, "call", ["free", p9]),
            SSAInstruction(None, "call", ["free", p3]),
            SSAInstruction(p5, "call", ["malloc", 256]),     # Reuses p1 after total reclaim
            SSAInstruction(None, "call", ["free", p5]),
            # 3. Block splitting on large freed chunk (256B -> 64B + remainder >= 176B -> 64B)
            SSAInstruction(p6, "call", ["malloc", 64]),
            SSAInstruction(p7, "call", ["malloc", 64]),
            SSAInstruction(None, "store_off", [p7, 0, 321, "i64"]),
            SSAInstruction(v4, "load_off", [p7, 0, "i64"]),
            SSAInstruction(p8, "add", [p6, 80]),
            SSAInstruction(diff76, "cmp_eq", [p7, p8]),      # Split chunk sits exactly 16+64=80B past p6
            SSAInstruction(None, "call", ["free", p7]),
            SSAInstruction(None, "call", ["free", p6]),
            SSAInstruction(eq_coalesce, "cmp_eq", [p4, p1]),
            SSAInstruction(eq_reclaim, "cmp_eq", [p5, p1]),
            SSAInstruction(eq_split_ok, "cmp_eq", [p6, p1]),
            SSAInstruction(s1, "add", [eq_coalesce, eq_reclaim]),
            SSAInstruction(s2, "add", [s1, eq_split_ok]),
            SSAInstruction(s3, "add", [s2, diff76]),
            SSAInstruction(ge_split_diff, "add", [v9, v4]),
            SSAInstruction(ans, "add", [s3, ge_split_diff]),
            SSAInstruction(None, "ret", [ans]),
        ]
        fn.blocks.append(b)
        wb = WasmBackend()
        ret, _, stats = wb.run_ssa_with_memory([fn], "wasm_freelist_e2e", fuel_budget=20_000_000)
        # 4 boolean invariants + 777 + 321 = 1102
        self.assertEqual(ret, 4 + 777 + 321)
        self.assertGreater(stats.get("fuel_consumed", 0), 0)

    def test_02_macho_64_x86_64_and_arm64_object_linker_and_unicorn_hybrid(self):
        """Links Mach-O x86_64 & ARM64 LLVM+Native objects with live relocations and Unicorn verification."""
        src = (
            "def mac_leaf(n: int) -> int:\n"
            "    s = 0\n"
            "    i = 0\n"
            "    while i < n:\n"
            "        s = s + (i * 3) + 1\n"
            "        i = i + 1\n"
            "    return s\n\n"
            "def mac_entry(x: int) -> int:\n"
            "    if x > 0:\n"
            "        return mac_leaf(x) + 10\n"
            "    return 0\n"
        )
        defs = [nd for nd in ast.parse(src).body if isinstance(nd, ast.FunctionDef)]
        s_leaf = lower_ast_to_ssa(defs[0], optimize=True)
        s_entry = lower_ast_to_ssa(defs[1], optimize=True)
        sb = SiliconSafetySandbox()
        expected = sum(i * 3 + 1 for i in range(6)) + 10

        for arch, triple in (("x86_64", "x86_64-apple-macosx"), ("arm64", "arm64-apple-macosx")):
            ll = LLVMBackend(opt_level=3, target_triple=triple)
            obj_ent = ll.emit_object(ll.compile_ir(ll.ssa_module_to_llvm_ir([s_entry]), optimize=True))
            m_llvm = load_macho_object(obj_ent, repo_name="mac_llvm")
            self.assertIn("mac_entry", m_llvm.symbols)

            m_nat = ObjectModule("mac_nat")
            m_nat.add_symbol("mac_leaf", NativeCodeGenerator(arch=arch, target_os="macos").compile_ssa(s_leaf).code_bytes, True)

            lnk = NativeObjectLinker()
            lnk.add_module(m_llvm)
            lnk.add_module(m_nat)
            lr = lnk.link(entry_symbol="mac_entry")
            self.assertGreaterEqual(lr["relocations_applied"], 1)

            off = lr["global_symbols"]["mac_entry"]
            emu = (
                sb.emulate_arm64(lr["combined_code"], args=[6], start_offset=off)
                if arch == "arm64"
                else sb.emulate_x86_64(lr["combined_code"], args=[6], abi="system_v", start_offset=off)
            )
            self.assertTrue(emu.is_safe_for_silicon)
            self.assertEqual(emu.return_value, expected)

        # Full OmniRepoCompiler cross-target macOS Mach-O dylib & executable emission
        r_m = os.path.join(self.test_dir, "repo_macos")
        os.makedirs(r_m)
        with open(os.path.join(r_m, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_macos", "language": "python", "exports": ["mac_leaf", "mac_entry", "omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_m, "mac.py"), "w", encoding="utf-8") as f:
            f.write(src + "\ndef omni_main(x: int) -> int:\n    return mac_entry(x)\n")

        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "mac_runs.db"))
        try:
            for arch, fmt, fname in (
                ("x86_64", "shared_lib", "libomni_x64.dylib"),
                ("arm64", "executable", "omni_arm64_macho"),
            ):
                out_p = os.path.join(self.test_dir, fname)
                res = comp.compile_repositories(
                    [r_m],
                    out_p,
                    target_format=fmt,
                    target_os="macos",
                    target_arch=arch,
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "mac_leaf": "native",
                        "mac_entry": "llvm",
                        "omni_main": "llvm",
                    },
                    audit_nonce=f"c68-mac-{arch}",
                )
                fa = res["stages"]["formal_audit"]
                self.assertTrue(fa["is_valid"])
                self.assertEqual(fa["format"], "Mach-O 64")
                h = res["stages"]["homeostasis"]
                self.assertTrue(h["heterogeneous_link"])
                self.assertEqual(h["hybrid_emitters_used"], ["llvm", "native"])
                self.assertIn("apple-macosx", h["llvm_target_triple"])
                self.assertGreater(res["stages"]["debug_info"]["line_mappings_count"], 0)
        finally:
            comp.close()

    def test_03_quad_language_polyglot_heterogeneous_homeostasis_e2e(self):
        """Compiles 4 languages (C + Rust + TypeScript + Go) heterogeneously across Native, LLVM & GCC."""
        dirs = {}
        for nm in ("repo_c", "repo_rs", "repo_ts", "repo_go"):
            d = os.path.join(self.test_dir, nm)
            os.makedirs(d)
            dirs[nm] = d

        with open(os.path.join(dirs["repo_c"], "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c", "language": "c", "exports": ["c_step"], "dependencies": []}, f)
        with open(os.path.join(dirs["repo_c"], "dsp.c"), "w", encoding="utf-8") as f:
            f.write("int64_t c_step(int64_t a, int64_t b) {\n    return (a * 3) + b;\n}\n")

        with open(os.path.join(dirs["repo_rs"], "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_rs", "language": "rust", "exports": ["rs_acc"], "dependencies": ["repo_c"]}, f)
        with open(os.path.join(dirs["repo_rs"], "agg.rs"), "w", encoding="utf-8") as f:
            f.write(
                "pub fn rs_acc(n: i64) -> i64 {\n"
                "    let mut s: i64 = 0;\n"
                "    let mut i: i64 = 0;\n"
                "    while i < n {\n"
                "        s = s + c_step(i, 5);\n"
                "        i = i + 1;\n"
                "    }\n"
                "    return s;\n"
                "}\n"
            )

        with open(os.path.join(dirs["repo_ts"], "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_ts", "language": "typescript", "exports": ["ts_adjust"], "dependencies": ["repo_rs"]}, f)
        with open(os.path.join(dirs["repo_ts"], "policy.ts"), "w", encoding="utf-8") as f:
            f.write("export function ts_adjust(n: number): number {\n    return rs_acc(n) * 2;\n}\n")

        with open(os.path.join(dirs["repo_go"], "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_go", "language": "go", "exports": ["omni_main"], "dependencies": ["repo_ts"]}, f)
        with open(os.path.join(dirs["repo_go"], "main.go"), "w", encoding="utf-8") as f:
            f.write("func omni_main(n int64) int64 {\n    return ts_adjust(n) + 7\n}\n")

        expected_10 = sum((i * 3) + 5 for i in range(10)) * 2 + 7  # 377
        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "poly_runs.db"))
        try:
            host_ext = ".dll" if sys.platform == "win32" else ".so"
            out_lib = os.path.join(self.test_dir, f"poly4_host{host_ext}")
            ts_eng = "gcc" if (sys.platform != "win32" and comp.gcc.supports_elf64) else "llvm"
            res = comp.compile_repositories(
                [dirs["repo_c"], dirs["repo_rs"], dirs["repo_ts"], dirs["repo_go"]],
                out_lib,
                target_format="shared_lib",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_function_overrides={
                    "c_step": "native",
                    "rs_acc": "llvm",
                    "ts_adjust": ts_eng,
                    "omni_main": "native",
                },
                audit_nonce="c68-poly-host",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            self.assertTrue(res["stages"]["homeostasis"]["heterogeneous_link"])
            self.assertGreater(res["stages"]["debug_info"]["line_mappings_count"], 0)

            lib = ctypes.CDLL(out_lib)
            try:
                lib.omni_main.argtypes = [ctypes.c_int64]
                lib.omni_main.restype = ctypes.c_int64
                self.assertEqual(lib.omni_main(10), expected_10)
            finally:
                _unload_cdll(lib)

            # On Linux / WSL2 GCC ELF64, compile 4-language pipeline across all 3 engines (Native+GCC+LLVM)
            if comp.gcc.supports_elf64:
                out_elf = os.path.join(self.test_dir, "poly4_tri_elf")
                res_elf = comp.compile_repositories(
                    [dirs["repo_c"], dirs["repo_rs"], dirs["repo_ts"], dirs["repo_go"]],
                    out_elf,
                    target_format="executable",
                    target_os="linux",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "c_step": "native",
                        "rs_acc": "gcc",
                        "ts_adjust": "llvm",
                        "omni_main": "gcc",
                    },
                    audit_nonce="c68-poly-elf3",
                )
                h_elf = res_elf["stages"]["homeostasis"]
                self.assertEqual(h_elf["hybrid_emitters_used"], ["gcc", "llvm", "native"])
                self.assertEqual(h_elf["binary_emitter_engine"], "hybrid:gcc+llvm+native")
                if sys.platform == "win32":
                    w_p = "/mnt/" + out_elf[0].lower() + out_elf[2:].replace("\\", "/")
                    p = subprocess.run(["wsl", "bash", "-c", f"chmod +x '{w_p}' && '{w_p}' 10"], capture_output=True, text=True, timeout=25)
                else:
                    os.chmod(out_elf, 0o755)
                    p = subprocess.run([out_elf, "10"], capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, expected_10 % 256)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
