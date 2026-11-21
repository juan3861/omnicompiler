"""
Alpha-C66 Empirical & Adversarial Verification Suite:
1. True Heterogeneous Per-Function Linking (`HomeostasisRouter` + `OmniRepoCompiler` + `NativeObjectLinker`)
   combining GCC `-O3`, LLVM 20.1.8 `-O3`, and Omni Native objects in a single linked PE64/ELF64 binary
   (both explicit overrides AND autonomous PGO-driven partitioning).
2. Wasmtime Linear-Memory Libc/Heap (`malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `memset`,
   `strlen`, `strcmp`, `abs`, `labs`) & Host Variadic `printf`/`puts` Bridge across all 4 engines.
3. Host-Adaptive 8-Lane AVX-512 Vectorizer -> EVEX ZMM `vfmadd213pd` Auto-Fusion E2E & CPUID safety.
4. `AssemblyInvariantAuditor` frame-pointer / GCC `-O3` YMM-spill epilogue teardown precision & mutant killing.
5. Zero-`ResourceWarning` hygiene across `IndependentValidator` persistent worker & benchmark corpus files.
"""

import ast
import ctypes
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.gcc_backend import GCCBackend
from compiler.homeostasis_router import EngineExecutionResult, HomeostasisRouter
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_codegen import X64CodeGenerator, detect_host_simd_features
from compiler.native_jit import NativeJitMemory
from compiler.object_linker import load_elf_object
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor


def _run_objdump_raw(code_bytes: bytes) -> str:
    """Disassembles raw x86-64 machine code bytes using native or WSL2 `/usr/bin/objdump`."""
    if sys.platform != "win32":
        objdump_bin = "/usr/bin/objdump" if os.path.exists("/usr/bin/objdump") else shutil.which("objdump")
        if not objdump_bin:
            return ""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(code_bytes)
            bin_path = tf.name
        try:
            p = subprocess.run(
                [objdump_bin, "-D", "-b", "binary", "-m", "i386:x86-64", bin_path],
                capture_output=True, text=True, timeout=15,
            )
            return p.stdout if p.returncode == 0 else ""
        finally:
            if os.path.exists(bin_path):
                os.remove(bin_path)

    if not GCCBackend().supports_elf64:
        return ""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(code_bytes)
        bin_path = tf.name
    try:
        wsl_p = "/mnt/" + bin_path[0].lower() + bin_path[2:].replace("\\", "/")
        p = subprocess.run(
            ["wsl", "/usr/bin/objdump", "-D", "-b", "binary", "-m", "i386:x86-64", wsl_p],
            capture_output=True, text=True, timeout=25,
        )
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def _unload_cdll(lib: Any) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if sys.platform == "win32" and handle:
        import _ctypes
        _ctypes.FreeLibrary(handle)


class TestAlphaC66HeterogeneousLinkingWasmLibcAndHygiene(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="omni_alpha_c66_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_heterogeneous_per_function_linking_native_llvm_and_gcc(self):
        """Links GCC O3 + LLVM 20 O3 + Omni Native objects per function inside one PE64/ELF64 binary."""
        r_core = os.path.join(self.test_dir, "repo_core")
        r_app = os.path.join(self.test_dir, "repo_app")
        os.makedirs(r_core)
        os.makedirs(r_app)

        with open(os.path.join(r_core, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_core", "language": "python", "exports": ["leaf_native", "mid_stage"], "dependencies": []}, f)
        with open(os.path.join(r_core, "core.py"), "w", encoding="utf-8") as f:
            f.write(
                "def leaf_native(x: int) -> int:\n"
                "    return (x * 5) + 11\n\n"
                "def mid_stage(x: int) -> int:\n"
                "    return leaf_native(x) + 100\n"
            )

        with open(os.path.join(r_app, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_app", "language": "python", "exports": ["outer_pipeline", "omni_main"], "dependencies": ["repo_core"]}, f)
        with open(os.path.join(r_app, "app.py"), "w", encoding="utf-8") as f:
            f.write(
                "def outer_pipeline(x: int) -> int:\n"
                "    return mid_stage(x) * 3\n\n"
                "def omni_main(x: int) -> int:\n"
                "    ans = outer_pipeline(x)\n"
                '    printf("HYB=%lld\\n", ans)\n'
                "    return ans % 251\n"
            )

        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "runs.db"))
        try:
            # Negative check: reject bogus per-function emitter names fail-closed
            with self.assertRaises(ValueError):
                comp.compile_repositories(
                    [r_core, r_app],
                    os.path.join(self.test_dir, "bad.dll"),
                    backend="homeostasis",
                    homeostasis_function_overrides={"leaf_native": "bogus_engine"},
                )

            # 1A. Host shared library mixing Native + LLVM (+ GCC on Linux)
            host_ext = ".dll" if sys.platform == "win32" else ".so"
            out_lib = os.path.join(self.test_dir, f"hybrid_host{host_ext}")
            mid_engine = "gcc" if (sys.platform != "win32" and comp.gcc.supports_elf64) else "llvm"
            overrides = {
                "leaf_native": "native",
                "mid_stage": mid_engine,
                "outer_pipeline": "llvm",
                "omni_main": "llvm",
            }
            res_host = comp.compile_repositories(
                [r_core, r_app],
                out_lib,
                target_format="shared_lib",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_function_overrides=overrides,
                audit_nonce="c66-hyb-host",
            )
            self.assertTrue(res_host["stages"]["formal_audit"]["is_valid"])
            h_host = res_host["stages"]["homeostasis"]
            self.assertTrue(h_host["heterogeneous_link"])
            self.assertTrue(h_host["binary_emitter_engine"].startswith("hybrid:"))
            self.assertIn("native", h_host["hybrid_emitters_used"])
            self.assertIn("llvm", h_host["hybrid_emitters_used"])
            if sys.platform != "win32" and comp.gcc.supports_elf64:
                self.assertIn("gcc", h_host["hybrid_emitters_used"])

            lib = ctypes.CDLL(out_lib)
            try:
                lib.outer_pipeline.argtypes = [ctypes.c_int64]
                lib.outer_pipeline.restype = ctypes.c_int64
                for x_val in (-7, 0, 12, 100):
                    self.assertEqual(lib.outer_pipeline(x_val), ((x_val * 5 + 11) + 100) * 3)
            finally:
                _unload_cdll(lib)

            # 1B. ELF64 executable mixing GCC + Native across both native Linux and WSL2
            if comp.gcc.supports_elf64:
                out_elf = os.path.join(self.test_dir, "hybrid_elf")
                res_elf = comp.compile_repositories(
                    [r_core, r_app],
                    out_elf,
                    target_format="executable",
                    target_os="linux",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "leaf_native": "native",
                        "mid_stage": "gcc",
                        "outer_pipeline": "gcc",
                        "omni_main": "gcc",
                    },
                    audit_nonce="c66-hyb-elf",
                )
                h_elf = res_elf["stages"]["homeostasis"]
                self.assertTrue(h_elf["heterogeneous_link"])
                self.assertEqual(h_elf["hybrid_emitters_used"], ["gcc", "native"])
                if sys.platform == "win32":
                    wsl_bin = "/mnt/" + out_elf[0].lower() + out_elf[2:].replace("\\", "/")
                    p = subprocess.run(["wsl", "bash", "-c", f"chmod +x '{wsl_bin}' && '{wsl_bin}' 12"], capture_output=True, text=True, timeout=25)
                else:
                    os.chmod(out_elf, 0o755)
                    p = subprocess.run([out_elf, "12"], capture_output=True, text=True, timeout=10)
                self.assertIn("HYB=513", p.stdout)
                self.assertEqual(p.returncode, 513 % 251)

            # 1C. Autonomous PGO-driven per-function partitioning WITHOUT overrides
            pgo_dir = os.path.join(self.test_dir, "auto_pgo_repos")
            os.makedirs(pgo_dir)
            r_auto = os.path.join(pgo_dir, "repo_auto")
            os.makedirs(r_auto)
            with open(os.path.join(r_auto, "omni_repo.json"), "w", encoding="utf-8") as f:
                json.dump({"name": "repo_auto", "language": "python", "exports": ["scalar_stage", "loop_stage", "omni_main"], "dependencies": []}, f)
            with open(os.path.join(r_auto, "auto.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def scalar_stage(x: int) -> int:\n"
                    "    return (x * 7) - 3\n\n"
                    "def loop_stage(n: int) -> int:\n"
                    "    acc = 0\n"
                    "    i = 0\n"
                    "    while i < n:\n"
                    "        acc += scalar_stage(i)\n"
                    "        i += 1\n"
                    "    return acc\n\n"
                    "def omni_main() -> int:\n"
                    "    return loop_stage(5)\n"
                )
            auto_comp = OmniRepoCompiler(db_path=os.path.join(pgo_dir, "auto_runs.db"))
            try:
                with open(os.path.join(r_auto, "auto.py"), "r", encoding="utf-8") as f_src:
                    src_text = f_src.read()
                parsed_defs = [nd for nd in ast.parse(src_text).body if isinstance(nd, ast.FunctionDef)]
                scalar_ssa = lower_ast_to_ssa(parsed_defs[0], optimize=True)
                loop_ssa = lower_ast_to_ssa(parsed_defs[1], optimize=True)

                # Seed PGO: scalar signature fastest on 'native'; loop signature fastest on 'llvm'
                from compiler.homeostasis_router import HomeostasisReport
                auto_comp.homeostasis.profile_store.record_report(
                    [scalar_ssa],
                    HomeostasisReport(
                        policy="throughput",
                        function_name="scalar_stage",
                        consensus_reached=True,
                        selected_engine="native",
                        consensus_value=11,
                        active_engines=["native", "llvm"],
                        results_by_engine={
                            "native": EngineExecutionResult("native", True, 11, elapsed_ms=0.04, simd_stats={"simd_instruction_count": 2}),
                            "llvm": EngineExecutionResult("llvm", True, 11, elapsed_ms=6.5, simd_stats={"simd_instruction_count": 2}),
                        },
                    ),
                )
                auto_comp.homeostasis.profile_store.record_report(
                    [loop_ssa],
                    HomeostasisReport(
                        policy="throughput",
                        function_name="loop_stage",
                        consensus_reached=True,
                        selected_engine="llvm",
                        consensus_value=0,
                        active_engines=["native", "llvm"],
                        results_by_engine={
                            "native": EngineExecutionResult("native", True, 0, elapsed_ms=5.0, simd_stats={"simd_instruction_count": 0}),
                            "llvm": EngineExecutionResult("llvm", True, 0, elapsed_ms=0.15, simd_stats={"simd_instruction_count": 12}),
                        },
                    ),
                )
                auto_lib = os.path.join(pgo_dir, f"auto_hybrid{host_ext}")
                res_auto = auto_comp.compile_repositories(
                    [r_auto],
                    auto_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    audit_nonce="c66-auto-pgo",
                )
                h_auto = res_auto["stages"]["homeostasis"]
                self.assertEqual(h_auto["function_emitters"]["scalar_stage"], "native")
                self.assertEqual(h_auto["function_emitters"]["loop_stage"], "llvm")
                self.assertTrue(h_auto["heterogeneous_link"])
                self.assertEqual(h_auto["hybrid_emitters_used"], ["llvm", "native"])
                alib = ctypes.CDLL(auto_lib)
                try:
                    alib.loop_stage.argtypes = [ctypes.c_int64]
                    alib.loop_stage.restype = ctypes.c_int64
                    self.assertEqual(alib.loop_stage(6), sum(i * 7 - 3 for i in range(6)))
                finally:
                    _unload_cdll(alib)
            finally:
                auto_comp.close()
        finally:
            comp.close()

    def test_02_wasm_linear_memory_libc_heap_and_host_stdio_consensus(self):
        """Tests WASM bump heap (malloc/calloc/realloc/free + memory.grow), mem/str/math & host printf consensus."""
        fn = SSAFunction("wasm_libc_e2e", ["x"], param_types={"x": "i64"}, return_type="i64")
        fn.cstrs = {
            "fmt": b"VAL=%lld F=%.2f S=%s\n\x00",
            "tag": b"omni\x00",
            "msg": b"WASM_PUTS_OK\x00",
        }
        b = BasicBlock("entry")
        x = SSAVar("x", 0, "i64")
        p1, p2, p3, p4 = [SSAVar(n, 0, "i64") for n in ("p1", "p2", "p3", "p4")]
        tag, fmt, msg = [SSAVar(n, 0, "i64") for n in ("tag", "fmt", "msg")]
        fp = SSAVar("fp", 0, "f64")
        ab, sl, eq0, eq1, v0, v1, v2, acc1, acc2, ans = [
            SSAVar(n, 0, "i64") for n in ("ab", "sl", "eq0", "eq1", "v0", "v1", "v2", "acc1", "acc2", "ans")
        ]
        b.instructions = [
            SSAInstruction(p1, "call", ["malloc", 64]),
            SSAInstruction(None, "call", ["memset", p1, 65, 16]),
            SSAInstruction(p2, "call", ["calloc", 4, 8]),
            SSAInstruction(None, "call", ["memcpy", p2, p1, 8]),
            SSAInstruction(None, "store_off", [p2, 0, 77, "i8"]),
            SSAInstruction(None, "store_off", [p2, 1, 78, "i8"]),
            # Overlapping memmove shift [0..4) -> [2..6)
            SSAInstruction(p3, "add", [p2, 2]),
            SSAInstruction(None, "call", ["memmove", p3, p2, 4]),
            SSAInstruction(v0, "load_off", [p2, 2, "i8"]),  # 77 ('M')
            SSAInstruction(p4, "call", ["realloc", p1, 128]),
            SSAInstruction(v1, "load_off", [p4, 7, "i8"]),  # 65 ('A')
            SSAInstruction(ab, "call", ["abs", x]),
            SSAInstruction(tag, "cstr_addr", ["tag"]),
            SSAInstruction(fmt, "cstr_addr", ["fmt"]),
            SSAInstruction(msg, "cstr_addr", ["msg"]),
            SSAInstruction(sl, "call", ["strlen", tag]),    # 4
            SSAInstruction(eq0, "call", ["strcmp", tag, tag]),  # 0
            SSAInstruction(fp, "const", [2.5]),
            SSAInstruction(None, "call", ["printf", fmt, ab, fp, tag]),
            SSAInstruction(None, "call", ["puts", msg]),
            SSAInstruction(None, "call", ["free", p2]),
            SSAInstruction(None, "call", ["free", p4]),
            SSAInstruction(v2, "add", [v0, v1]),
            SSAInstruction(acc1, "add", [v2, ab]),
            SSAInstruction(acc2, "add", [acc1, sl]),
            SSAInstruction(ans, "add", [acc2, eq0]),
            SSAInstruction(None, "ret", [ans]),
        ]
        fn.blocks.append(b)

        expected_ret = 77 + 65 + 35 + 4
        wb = WasmBackend()
        ret_w, _, stats_w = wb.run_ssa_with_memory([fn], "wasm_libc_e2e", args=[-35])
        self.assertEqual(ret_w, expected_ret)
        self.assertIn("VAL=35 F=2.50 S=omni", stats_w.get("captured_stdout", ""))
        self.assertIn("WASM_PUTS_OK", stats_w.get("captured_stdout", ""))

        # Verify large heap growth (> 256 KiB via memory.grow) in WASM
        grow_fn = SSAFunction("wasm_heap_grow", [], return_type="i64")
        gb = BasicBlock("entry")
        ha, hb, va, vb, ssum = [SSAVar(n, 0, "i64") for n in ("ha", "hb", "va", "vb", "ssum")]
        gb.instructions = [
            SSAInstruction(ha, "call", ["malloc", 200000]),
            SSAInstruction(hb, "call", ["malloc", 200000]),
            SSAInstruction(None, "store_off", [ha, 190000, 111, "i64"]),
            SSAInstruction(None, "store_off", [hb, 190000, 222, "i64"]),
            SSAInstruction(va, "load_off", [ha, 190000, "i64"]),
            SSAInstruction(vb, "load_off", [hb, 190000, "i64"]),
            SSAInstruction(ssum, "add", [va, vb]),
            SSAInstruction(None, "call", ["free", hb]),
            SSAInstruction(None, "call", ["free", ha]),
            SSAInstruction(None, "ret", [ssum]),
        ]
        grow_fn.blocks.append(gb)
        ret_grow, _, _ = wb.run_ssa_with_memory([grow_fn], "wasm_heap_grow")
        self.assertEqual(ret_grow, 333)

        # Full quad-ecosystem consensus on malloc/calloc/realloc/free/memset/memcpy/abs/strlen/printf
        router = HomeostasisRouter()
        try:
            rep = router.execute_differential([fn], "wasm_libc_e2e", args=[-35], policy="consensus")
            self.assertTrue(rep.consensus_reached, rep.divergences)
            self.assertEqual(rep.isolated_engines, [], rep.divergences)
            self.assertEqual(rep.consensus_value, expected_ret)
            self.assertIn("native", rep.active_engines)
            self.assertIn("llvm", rep.active_engines)
            self.assertIn("wasm", rep.active_engines)
            if router.gcc_backend.is_available:
                self.assertIn("gcc", rep.active_engines)
        finally:
            router.close()

    def test_03_loop_vectorizer_8lane_avx512_zmm_autofusion_e2e(self):
        """Verifies LoopVectorizer 8-lane AVX512_512 mode triggers EVEX ZMM vfmadd213pd autofusion + CPUID gate."""
        src = (
            "def raw_fma_f64(a: int, b: int, c: int, out: int, n: int) -> int:\n"
            "    i = 0\n"
            "    while i < n:\n"
            "        off = i * 8\n"
            "        va = load_f64(a, off)\n"
            "        vb = load_f64(b, off)\n"
            "        vc = load_f64(c, off)\n"
            "        store_f64(out, off, va * vb + vc)\n"
            "        i = i + 1\n"
            "    return n\n"
        )
        ssa = lower_ast_to_ssa(ast.parse(src).body[0], optimize=True)
        ssa_v, stats = LoopVectorizerPass().vectorize_vla_function(ssa, target_isa="AVX512_512")
        self.assertEqual(stats["vla_lanes"], 8)
        self.assertGreaterEqual(stats["vectorized_stores"], 1)

        cg_zmm = X64CodeGenerator(enable_avx2=True, enable_fma=True, enable_avx512=True, enable_avx512dq=True)
        art_zmm = cg_zmm.compile_function(ssa_v)
        self.assertIn(b"\x62", art_zmm.code_bytes)
        disasm = _run_objdump_raw(art_zmm.code_bytes)
        if disasm:
            self.assertIn("zmm0", disasm)
            self.assertIn("vmovdqu64", disasm)
            self.assertIn("vfmadd213pd", disasm)

        feats = detect_host_simd_features()
        if feats.get("avx512f", False) and not sys.platform.startswith("win"):
            mem = NativeJitMemory(size=max(4096, len(art_zmm.code_bytes)))
            try:
                mem.write_code(art_zmm.code_bytes)
                cf = ctypes.CFUNCTYPE(
                    ctypes.c_int64,
                    ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64,
                )(mem.ptr)
                for n_el in (0, 3, 8, 15, 24):
                    a = (ctypes.c_double * max(1, n_el))(*[1.5 * k + 0.5 for k in range(n_el)])
                    b = (ctypes.c_double * max(1, n_el))(*[2.0 + 0.25 * k for k in range(n_el)])
                    c = (ctypes.c_double * max(1, n_el))(*[-3.0 + 0.1 * k for k in range(n_el)])
                    out = (ctypes.c_double * max(1, n_el))()
                    rc = cf(
                        ctypes.addressof(a), ctypes.addressof(b),
                        ctypes.addressof(c), ctypes.addressof(out), n_el,
                    )
                    self.assertEqual(rc, n_el)
                    for k in range(n_el):
                        self.assertAlmostEqual(out[k], a[k] * b[k] + c[k], places=10)
            finally:
                mem.free()
        else:
            # Verify host CPUID safety on AVX2-only hosts
            cg_safe = X64CodeGenerator(enable_avx512=False)
            art_safe = cg_safe.compile_function(ssa_v)
            self.assertNotIn(b"\x62\xf2", art_safe.code_bytes)

    def test_04_assembly_auditor_gcc_frame_teardown_and_mutant_killing(self):
        """Verifies GCC -O3 YMM-aligned lea-rbp epilogues pass audit while unbalanced mutants fail closed."""
        auditor = AssemblyInvariantAuditor()
        # Synthetic YMM-aligned frame-pointer prologue/epilogue with interleaved imul (0xEB ModRM):
        # push rbp; mov rbp, rsp; push r12; push rbx; and rsp, -32; sub rsp, 32; ...
        # lea -16(rbp), rsp; imul rbx (48 f7 eb); pop rbx; pop r12; pop rbp; ret
        valid_fp_frame = (
            b"\x55\x48\x89\xe5\x41\x54\x53\x48\x83\xe4\xe0\x48\x83\xec\x20"
            b"\xb8\x2a\x00\x00\x00"
            b"\x48\x8d\x65\xf0\x48\xf7\xeb\x5b\x41\x5c\x5d\xc3"
        )
        rep_ok = auditor.audit_function_code(valid_fp_frame, "gcc_ymm_epilogue")
        self.assertTrue(rep_ok.is_valid, rep_ok.errors)
        self.assertTrue(rep_ok.stack_balanced)

        # Mutant: lea 0(rbp), rsp forgets -8 offset for 'push rbx' -> MUST FAIL!
        bad_disp_mutant = (
            b"\x55\x48\x89\xe5\x53\x48\x83\xec\x20"
            b"\x48\x8d\x65\x00\x5b\x5d\xc3"
        )
        rep_bad = auditor.audit_function_code(bad_disp_mutant, "mutant_wrong_lea_disp")
        self.assertFalse(rep_bad.is_valid)
        self.assertFalse(rep_bad.stack_balanced)
        self.assertTrue(any("Stack frame imbalance" in e for e in rep_bad.errors))

        # Live GCC -O3 separated omni_main ELF object check (when GCC ELF64 is available)
        gcc = GCCBackend(opt_level=3)
        if gcc.supports_elf64:
            src = (
                "def vec_kernel(buf: int, n: int) -> int:\n"
                "    return n\n\n"
                "def omni_main(n: int) -> int:\n"
                "    n_cl = n\n"
                "    if n_cl < 0:\n"
                "        n_cl = 0\n"
                "    if n_cl > 24:\n"
                "        n_cl = 24\n"
                "    buf = malloc(768)\n"
                "    k = 0\n"
                "    while k < n_cl:\n"
                "        store_i64(buf, k * 8, k * 5 + 3)\n"
                "        store_i64(buf, 256 + k * 8, k * 2 + 1)\n"
                "        k += 1\n"
                "    tot = vec_kernel(buf, n_cl)\n"
                "    free(buf)\n"
                '    printf("OK=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )
            only_main = lower_ast_to_ssa(ast.parse(src).body[1], optimize=True)
            obj = gcc.emit_object([only_main], target_os="linux")
            mod = load_elf_object(obj, repo_name="gcc_sep")
            sd = mod.symbols["omni_main"]
            code_slice = bytes(mod.text_bytes[sd.offset : sd.offset + sd.size])
            rep_real = auditor.audit_function_code(code_slice, "omni_main")
            self.assertTrue(rep_real.is_valid, rep_real.errors)

    def test_05_zero_resource_warning_hygiene_subprocess_check(self):
        """Verifies IndependentValidator worker cleanup and benchmark modules leak zero open file warnings."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in (
            "benchmarks/benchmark_frontier_14.py",
            "benchmarks/benchmark_frontier_28.py",
            "benchmarks/corpus_p4.py",
            "evolution/continuous_evolution_daemon.py",
        ):
            with open(os.path.join(root, rel), "r", encoding="utf-8") as f_chk:
                txt = f_chk.read()
            self.assertIsNone(re.search(r"json\.(?:load|dump)\([^)]*\bopen\(", txt), f"Unclosed open() in {rel}")

        probe_code = (
            "from validation.validator import IndependentValidator; "
            "v = IndependentValidator(); "
            "IndependentValidator.close_persistent_worker()"
        )
        p = subprocess.run(
            [sys.executable, "-W", "error::ResourceWarning", "-c", probe_code],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(p.returncode, 0, f"stderr={p.stderr}")


if __name__ == "__main__":
    unittest.main()
