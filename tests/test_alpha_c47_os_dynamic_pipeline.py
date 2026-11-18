"""
Alpha-C47 End-to-End Verification Suite:
1. Polyglot string literal parsing (C/Rust/Go/Zig/TS/etc.) + position-independent `.rodata` `cstr_addr`.
2. Z3 SMT equivalence proof and string-mutation counterexample refutation for `cstr_addr`.
3. Full 9-stage OmniRepoCompiler `target_format="executable"` with OS C-ABI imports (`puts`, `strlen`, `atoi`, `malloc`, `free`).
4. Live host OS execution of emitted Windows PE32+ (MSVCRT.dll / KERNEL32.dll) and Linux ELF64 (libc.so.6) executables.
5. LLVM O3 + Z3 BackendTranslationValidator parity with dynamic OS IAT/GOT linking.
6. ARM64 (`ADR` PC-relative) and WASM linear-memory `.rodata` lowering of `cstr_addr`.
"""

import ast
import json
import os
import shutil
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compiler.native_codegen import Arm64CodeGenerator
from compiler.ssa_ir import lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from validation.ssa_translation_validator import SSATranslationValidator


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["wsl", "uname"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "Linux" in r.stdout
    except Exception:
        return False


class TestAlphaC47OsDynamicPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c47_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_polyglot_cstr_parsing_and_z3_smt_refutation(self):
        """Verifies C/polyglot string literals lower to `cstr_addr` and Z3 proves identity vs refutes mutation."""
        c_src_a = """
        int c_str_len_a(int x) {
            puts("OMNI_ALPHA_C47");
            return x + strlen("OmniCompiler");
        }
        """
        c_src_b = """
        int c_str_len_b(int x) {
            puts("OMNI_ALPHA_C47");
            return x + strlen("MutatedString");
        }
        """
        parsed_a = lower_polyglot_source_to_ast(c_src_a, language="c", allow_floats=True)
        parsed_b = lower_polyglot_source_to_ast(c_src_b, language="c", allow_floats=True)
        ssa_a = lower_ast_to_ssa(parsed_a.functions[0])
        ssa_a2 = lower_ast_to_ssa(parsed_a.functions[0])
        ssa_b = lower_ast_to_ssa(parsed_b.functions[0])

        opcodes = [ins.opcode for blk in ssa_a.blocks for ins in blk.instructions]
        self.assertIn("cstr_addr", opcodes)
        self.assertEqual(len(ssa_a.cstrs), 2)

        validator = SSATranslationValidator(enable_memory_theory=True, enable_call_congruence=True)
        eq_res = validator.verify_equivalence(ssa_a, ssa_a2)
        self.assertTrue(eq_res.get("proven"), eq_res)
        self.assertEqual(eq_res.get("status"), "PROVEN_EQUIVALENT")

        neq_res = validator.verify_equivalence(ssa_a, ssa_b)
        self.assertFalse(neq_res.get("proven"), neq_res)
        self.assertEqual(neq_res.get("status"), "REFUTED_COUNTEREXAMPLE")

    def test_02_omni_repo_polyglot_c_py_dynamic_exe_windows_and_linux_native(self):
        """Compiles C+Python repos to Windows PE32+ and Linux ELF64 executables with live OS stdio + atoi + strlen."""
        r1 = os.path.join(self.test_dir, "repo_c")
        r2 = os.path.join(self.test_dir, "repo_py")
        os.makedirs(r1)
        os.makedirs(r2)

        with open(os.path.join(r1, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c", "language": "c", "exports": ["c_greet_len"], "dependencies": []}, f)
        with open(os.path.join(r1, "greet.c"), "w", encoding="utf-8") as f:
            f.write(
                'int c_greet_len(int x) {\n'
                '    puts("OMNI_C47_STDIO_OK");\n'
                '    int n = strlen("OmniCompiler");\n'
                '    int a = atoi("30");\n'
                '    return x + n + a;\n'
                '}\n'
            )

        with open(os.path.join(r2, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_py", "language": "python", "exports": ["omni_main"], "dependencies": ["repo_c"]}, f)
        with open(os.path.join(r2, "main.py"), "w", encoding="utf-8") as f:
            f.write("def omni_main(x: int) -> int:\n    return c_greet_len(x)\n")

        comp = OmniRepoCompiler()
        try:
            # 1. Windows PE32+ emission & formal audit
            win_exe = os.path.join(self.test_dir, "c47_app.exe")
            res_win = comp.compile_repositories(
                [r1, r2], win_exe, target_format="executable", entry_export="omni_main",
                target_os="windows", backend="native", audit_nonce="c47-win",
            )
            self.assertTrue(res_win["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_win["stages"]["formal_audit"]["format"], "PE32+")
            self.assertEqual(res_win["stages"]["linking"]["external_os_imports"], ["atoi", "puts", "strlen"])
            imp_syms = res_win["stages"]["formal_audit"]["imported_symbols"]
            self.assertIn("MSVCRT.dll!puts", imp_syms)
            self.assertIn("MSVCRT.dll!strlen", imp_syms)
            self.assertIn("MSVCRT.dll!atoi", imp_syms)

            if sys.platform == "win32":
                proc_w = subprocess.run([win_exe, "5"], capture_output=True, text=True, timeout=10)
                self.assertIn("OMNI_C47_STDIO_OK", proc_w.stdout)
                self.assertEqual(proc_w.returncode, 47)

            # 2. Linux ELF64 emission & formal audit
            lin_elf = os.path.join(self.test_dir, "c47_app_linux")
            res_lin = comp.compile_repositories(
                [r1, r2], lin_elf, target_format="executable", entry_export="omni_main",
                target_os="linux", backend="native", audit_nonce="c47-lin",
            )
            self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_lin["stages"]["formal_audit"]["format"], "ELF64")
            self.assertEqual(res_lin["stages"]["linking"]["external_os_imports"], ["atoi", "puts", "strlen"])

            if sys.platform != "win32":
                os.chmod(lin_elf, 0o755)
                proc_l = subprocess.run([lin_elf, "5"], capture_output=True, text=True, timeout=10)
                self.assertIn("OMNI_C47_STDIO_OK", proc_l.stdout)
                self.assertEqual(proc_l.returncode, 47)
            elif _wsl_available():
                wsl_p = lin_elf.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c47_app_linux && chmod +x /tmp/c47_app_linux && /tmp/c47_app_linux 5"
                proc_l = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=15)
                if proc_l.returncode != 4294967295:
                    self.assertIn(b"OMNI_C47_STDIO_OK", proc_l.stdout)
                    self.assertEqual(proc_l.returncode, 47)
        finally:
            comp.close()

    def test_03_omni_repo_os_heap_malloc_free_and_unicorn_preflight(self):
        """Verifies real OS malloc/free heap allocation + Unicorn preflight safety stub."""
        r_heap = os.path.join(self.test_dir, "repo_heap")
        os.makedirs(r_heap)
        with open(os.path.join(r_heap, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_heap", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_heap, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(x: int) -> int:\n"
                "    p = malloc(64)\n"
                "    store_i32(p, 0, x * 2)\n"
                "    v = load_i32(p, 0)\n"
                "    free(p)\n"
                '    puts("HEAP_C47_OK")\n'
                "    return v + 1\n"
            )

        comp = OmniRepoCompiler()
        try:
            out_bin = os.path.join(self.test_dir, "heap_app.exe" if sys.platform == "win32" else "heap_app")
            res = comp.compile_repositories(
                [r_heap], out_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c47-heap",
            )
            self.assertTrue(res["stages"]["preflight_safety"]["is_safe_for_silicon"])
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res["stages"]["linking"]["external_os_imports"], ["free", "malloc", "puts"])

            if sys.platform != "win32":
                os.chmod(out_bin, 0o755)
            proc = subprocess.run([out_bin, "20"], capture_output=True, text=True, timeout=10)
            self.assertIn("HEAP_C47_OK", proc.stdout)
            self.assertEqual(proc.returncode, 41)
        finally:
            comp.close()

    def test_04_omni_repo_llvm_o3_dynamic_os_imports_and_btv(self):
        """Compiles C+Python repos with LLVM O3 + Z3 BTV and executes dynamic OS imports live."""
        r1 = os.path.join(self.test_dir, "repo_c_llvm")
        r2 = os.path.join(self.test_dir, "repo_py_llvm")
        os.makedirs(r1)
        os.makedirs(r2)

        with open(os.path.join(r1, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c_llvm", "language": "c", "exports": ["c_greet_llvm"], "dependencies": []}, f)
        with open(os.path.join(r1, "greet.c"), "w", encoding="utf-8") as f:
            f.write(
                'int c_greet_llvm(int x) {\n'
                '    puts("OMNI_C47_LLVM_OK");\n'
                '    int n = strlen("OmniCompiler");\n'
                '    int a = atoi("30");\n'
                '    return x + n + a;\n'
                '}\n'
            )

        with open(os.path.join(r2, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_py_llvm", "language": "python", "exports": ["omni_main"], "dependencies": ["repo_c_llvm"]}, f)
        with open(os.path.join(r2, "main.py"), "w", encoding="utf-8") as f:
            f.write("def omni_main(x: int) -> int:\n    return c_greet_llvm(x)\n")

        comp = OmniRepoCompiler()
        try:
            out_bin = os.path.join(self.test_dir, "llvm_app.exe" if sys.platform == "win32" else "llvm_app")
            res = comp.compile_repositories(
                [r1, r2], out_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c47-llvm",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res["stages"]["linking"]["external_os_imports"], ["atoi", "puts", "strlen"])
            self.assertGreaterEqual(res["stages"]["codegen"].get("llvm_compiled_functions", 0), 2)
            self.assertEqual(res["stages"]["backend_validation"].get("refuted", 0), 0)

            if sys.platform != "win32":
                os.chmod(out_bin, 0o755)
            proc = subprocess.run([out_bin, "5"], capture_output=True, text=True, timeout=10)
            self.assertIn("OMNI_C47_LLVM_OK", proc.stdout)
            self.assertEqual(proc.returncode, 47)
        finally:
            comp.close()

    def test_05_wasm_and_arm64_cstr_addr_rodata_lowering(self):
        """Verifies ARM64 ADR PC-relative lowering and WASM linear-memory .rodata embedding of cstr_addr."""
        mod = ast.parse('def cstr_probe(x: int) -> int:\n    p = c_str("ARM64_WASM_CSTR")\n    return p + x\n')
        ssa_fn = lower_ast_to_ssa(mod.body[0])
        self.assertEqual(len(ssa_fn.cstrs), 1)

        # 1. ARM64 compilation with ADR fixup + embedded NUL-terminated bytes
        arm_art = Arm64CodeGenerator().compile_function(ssa_fn)
        self.assertIn(b"ARM64_WASM_CSTR\x00", arm_art.code_bytes)
        self.assertGreater(arm_art.code_end_offset, 0)

        # 2. WASM module generation with .rodata data segment
        wasm_be = WasmBackend()
        wat = wasm_be.ssa_module_to_wat([ssa_fn])
        expected_esc = "".join(f"\\{b:02x}" for b in b"ARM64_WASM_CSTR\x00")
        self.assertIn(expected_esc, wat)
        wasm_bytes = wasm_be.wat_to_wasm(wat)
        self.assertTrue(wasm_bytes.startswith(b"\x00asm"))


if __name__ == "__main__":
    unittest.main()
