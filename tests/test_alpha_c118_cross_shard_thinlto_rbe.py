"""Alpha-C118 verification: Real Cross-Shard ThinLTO Function Importing + RBEClusterPool CAS."""

import ctypes
import os
import subprocess
import sys
import tempfile
import unittest

from compiler.llvm_backend import LLVMBackend
from compiler.object_linker import NativeObjectLinker, load_coff_object, load_elf_object
from omni_repo_compiler import OmniRepoCompiler
from orchestrator.rbe_cas import ContentAddressableStore, RBEClusterPool


def _to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class TestAlphaC118CrossShardThinLtoRbe(unittest.TestCase):
    def test_01_cross_shard_thinlto_inlines_hot_helper_and_hits_rbe_cas(self) -> None:
        triple = "x86_64-pc-windows-msvc" if sys.platform == "win32" else "x86_64-unknown-linux-gnu"
        lb = LLVMBackend(target_triple=triple)

        # Shard 0 donor: tiny hot helper (3 IR insts) + big cold function (> 35 insts)
        cold_body = "\n".join(
            f"  %c{i+1} = add i32 %c{i}, {(i % 7) + 1}"
            for i in range(36)
        )
        ir_shard0 = (
            f'target triple = "{triple}"\n'
            'define dso_local i32 @c118_hot_mul_add(i32 %a) {\n'
            '  %m = mul i32 %a, 11\n'
            '  %s = add i32 %m, 5\n'
            '  ret i32 %s\n'
            '}\n'
            'define dso_local i32 @c118_cold_big(i32 %c0) {\n'
            f'{cold_body}\n'
            '  ret i32 %c36\n'
            '}\n'
        )
        # Shard 1 importer: calls c118_hot_mul_add (expects full cross-shard inline!)
        ir_shard1 = (
            f'target triple = "{triple}"\n'
            'declare i32 @c118_hot_mul_add(i32)\n'
            'define dso_local i32 @c118_shard1_driver(i32 %x) {\n'
            '  %r = call i32 @c118_hot_mul_add(i32 %x)\n'
            '  %z = add i32 %r, 7\n'
            '  ret i32 %z\n'
            '}\n'
        )

        with tempfile.TemporaryDirectory() as tmp:
            cas = ContentAddressableStore(os.path.join(tmp, "rbe_cas"))
            with RBEClusterPool(cas, num_workers=2, prefer_grpc=True) as pool:
                res1 = lb.thin_lto_partition(
                    [ir_shard0, ir_shard1],
                    num_shards=2,
                    inline_inst_threshold=16,
                    hot_weights={"c118_hot_mul_add": 1000},
                    rbe_pool=pool,
                )
                self.assertEqual(res1["num_shards"], 2)
                self.assertEqual(res1["rbe_cache_hits"], 0)
                self.assertGreaterEqual(res1["imported_functions_count"], 1)
                imp_syms = {r["symbol"] for r in res1["imported_functions"]}
                self.assertIn("c118_hot_mul_add", imp_syms)
                self.assertNotIn("c118_cold_big", imp_syms)

                # Cold run vs Warm CAS run: 100% CAS hit across RBE shards!
                res2 = lb.thin_lto_partition(
                    [ir_shard0, ir_shard1],
                    num_shards=2,
                    inline_inst_threshold=16,
                    hot_weights={"c118_hot_mul_add": 1000},
                    rbe_pool=pool,
                )
                self.assertEqual(res2["rbe_cache_hits"], 2)
                self.assertEqual(res1["shard_objects"], res2["shard_objects"])

            loader = load_coff_object if sys.platform == "win32" else load_elf_object
            mod0 = loader(res1["shard_objects"][0], repo_name="shard0")
            mod1 = loader(res1["shard_objects"][1], repo_name="shard1")
            # Cross-shard inline proof: c118_hot_mul_add was inlined into c118_shard1_driver,
            # leaving ZERO external call relocation to c118_hot_mul_add in shard 1,
            # and ZERO duplicate c118_hot_mul_add symbol in shard 1 (available_externally dropped!).
            self.assertNotIn("c118_hot_mul_add", [r.symbol_name for r in mod1.relocations])
            self.assertNotIn("c118_hot_mul_add", mod1.symbols)
            self.assertIn("c118_hot_mul_add", mod0.symbols)

            lnk = NativeObjectLinker(target_os="windows" if sys.platform == "win32" else "linux")
            lnk.add_module(mod0)
            lnk.add_module(mod1)
            out_bin = lnk.emit_linked_shared_library(
                os.path.join(tmp, "c118_thinlto"),
                export_name="c118_shard1_driver",
                target_format="pe_dll" if sys.platform == "win32" else "elf_so",
            )
            if sys.platform == "win32":
                lib = ctypes.CDLL(out_bin)
                try:
                    lib.c118_shard1_driver.argtypes = [ctypes.c_int32]
                    lib.c118_shard1_driver.restype = ctypes.c_int32
                    self.assertEqual(lib.c118_shard1_driver(4), 56)
                finally:
                    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    k32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    k32.FreeLibrary(ctypes.c_void_p(lib._handle))
            elif sys.platform == "linux":
                lib = ctypes.CDLL(out_bin)
                lib.c118_shard1_driver.argtypes = [ctypes.c_int32]
                lib.c118_shard1_driver.restype = ctypes.c_int32
                self.assertEqual(lib.c118_shard1_driver(4), 56)

    def test_02_omnirepo_e2e_thinlto_imported_functions_stage_telemetry(self) -> None:
        triple = "x86_64-pc-windows-msvc" if sys.platform == "win32" else "x86_64-unknown-linux-gnu"
        with tempfile.TemporaryDirectory() as tmp:
            ra = os.path.join(tmp, "repo_a")
            rb = os.path.join(tmp, "repo_b")
            os.makedirs(ra, exist_ok=True)
            os.makedirs(rb, exist_ok=True)

            with open(os.path.join(ra, "u0.ll"), "w", encoding="utf-8") as f:
                f.write(
                    f'target triple = "{triple}"\n'
                    'define dso_local i32 @c118_leaf_sq(i32 %x) {\n'
                    '  %r = mul i32 %x, %x\n'
                    '  ret i32 %r\n'
                    '}\n'
                )
            with open(os.path.join(rb, "u1.ll"), "w", encoding="utf-8") as f:
                f.write(
                    f'target triple = "{triple}"\n'
                    'declare i32 @c118_leaf_sq(i32)\n'
                    'define dso_local i32 @c118_e2e_main(i32 %v) {\n'
                    '  %sq = call i32 @c118_leaf_sq(i32 %v)\n'
                    '  %ans = add i32 %sq, 9\n'
                    '  ret i32 %ans\n'
                    '}\n'
                )

            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[ra, rb],
                    output_path=os.path.join(tmp, "c118_e2e_lib"),
                    target_format="shared_lib",
                    entry_export="c118_e2e_main",
                    toolchain_mode="federated_lto",
                    distributed_workers=2,
                    export_all=True,
                    emit_provenance=False,
                )
            finally:
                comp.close()

            fed = res["stages"]["federation"]
            self.assertEqual(fed.get("thin_lto_shards"), 2)
            self.assertGreaterEqual(fed.get("thin_lto_imported_functions", 0), 1)
            art = res["stages"]["emission"]["artifact_path"]
            if sys.platform == "win32":
                lib = ctypes.CDLL(art)
                try:
                    lib.c118_e2e_main.argtypes = [ctypes.c_int32]
                    lib.c118_e2e_main.restype = ctypes.c_int32
                    self.assertEqual(lib.c118_e2e_main(9), 90)
                finally:
                    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    k32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    k32.FreeLibrary(ctypes.c_void_p(lib._handle))
            elif sys.platform == "linux":
                lib = ctypes.CDLL(art)
                lib.c118_e2e_main.argtypes = [ctypes.c_int32]
                lib.c118_e2e_main.restype = ctypes.c_int32
                self.assertEqual(lib.c118_e2e_main(9), 90)


if __name__ == "__main__":
    unittest.main()
