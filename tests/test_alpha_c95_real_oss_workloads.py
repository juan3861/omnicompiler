"""
Alpha-C95 Empirical Verification Suite: Real OSS Polyglot Workloads & Dynamic Shared-Library OS Linking.

Verifies:
1. Real dynamic OS linking (`malloc`/`free`/`abs`) inside native shared libraries across
   PE64 `.dll` (Windows `.idata`), ELF64 `.so` (`x86_64` and `arm64`, `DT_NEEDED`/`DF_BIND_NOW`),
   and Mach-O 64 `.dylib` (`arm64`, `LC_LOAD_DYLIB`/`LC_DYLD_INFO_ONLY` + Ad-Hoc CodeSign),
   verified structurally AND executed live on host via `ctypes.CDLL`.
2. Expanded polyglot AOT subset across Rust, Go, TypeScript, and C:
   - Fixed local array literals (`[...]`, `[val; N]`, Go `[]int64{...}`, C `{...}`) + `.len()`/`.length`
   - Stack-promoted local structs & struct literals with C-ABI offset access
   - Inline closures/lambdas (`|k| ...`, `(z) => ...`, `func(k int64) int64 { ... }`)
   - Cross-module `import` / `use` / `#include` tracking & qualified cross-repo calls
3. End-to-end 4-repository heterogeneous C + Go + Rust + TypeScript workload compiled into a
   single native shared library and validated live through `ctypes.CDLL`.
"""

import ast
import ctypes
import os
import platform
import sys
import tempfile
import unittest

from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from validation.binary_structure_auditor import BinaryStructureAuditor


def _unload_shared_lib(lib: ctypes.CDLL) -> None:
    if platform.system() == "Windows":
        import _ctypes
        _ctypes.FreeLibrary(lib._handle)


class TestAlphaC95RealOSSWorkloads(unittest.TestCase):
    def test_01_shared_library_dynamic_os_linking_cross_platform(self):
        src = """
def dyn_heap_kernel(n: int) -> int:
    ptr = malloc(64)
    if ptr == 0:
        return -1
    store_i64(ptr, 0, (n * 10) + abs(-7))
    store_i64(ptr, 8, n + 3)
    res = load_i64(ptr, 0) + load_i64(ptr, 8)
    free(ptr)
    return res
"""
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "dyn_repo")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "dyn_mod.py"), "w", encoding="utf-8") as f:
                f.write(src)

            comp = OmniRepoCompiler()
            auditor = BinaryStructureAuditor()
            try:
                # 1. Windows PE64 DLL + structural .idata audit
                dll_path = os.path.join(td, "dyn_x64.dll")
                res_pe = comp.compile_repositories(
                    [repo_dir],
                    dll_path,
                    target_format="shared_lib",
                    entry_export="dyn_heap_kernel",
                    target_os="windows",
                    target_arch="x86_64",
                    export_all=True,
                )
                self.assertTrue(res_pe["success"], res_pe)
                with open(dll_path, "rb") as bf:
                    pe_audit = auditor.audit_binary(bf.read())
                self.assertTrue(pe_audit.is_valid, pe_audit)
                self.assertEqual(pe_audit.format, "PE32+")
                self.assertIn("MSVCRT.dll!malloc", pe_audit.imported_symbols)
                self.assertIn("MSVCRT.dll!free", pe_audit.imported_symbols)
                self.assertIn("dyn_heap_kernel", pe_audit.exported_symbols)

                # 2. Linux ELF64 .so (x86_64 & arm64) + DT_NEEDED / .dynsym audit
                for t_arch, so_name, exp_arch in (
                    ("x86_64", "libdyn_x86_64.so", "x86-64"),
                    ("arm64", "libdyn_arm64.so", "ARM64"),
                ):
                    so_path = os.path.join(td, so_name)
                    res_elf = comp.compile_repositories(
                        [repo_dir],
                        so_path,
                        target_format="shared_lib",
                        entry_export="dyn_heap_kernel",
                        target_os="linux",
                        target_arch=t_arch,
                        export_all=True,
                    )
                    self.assertTrue(res_elf["success"], res_elf)
                    with open(so_path, "rb") as bf:
                        elf_audit = auditor.audit_binary(bf.read())
                    self.assertTrue(elf_audit.is_valid, elf_audit)
                    self.assertEqual(elf_audit.machine_arch, exp_arch)
                    self.assertIn("libc.so.6", elf_audit.metrics.get("needed_libs", []))
                    self.assertIn("malloc", elf_audit.imported_symbols)
                    self.assertIn("free", elf_audit.imported_symbols)
                    self.assertIn("dyn_heap_kernel", elf_audit.exported_symbols)

                # 3. macOS ARM64 .dylib + LC_LOAD_DYLIB / LC_DYLD_INFO_ONLY / CodeSign audit
                dylib_path = os.path.join(td, "libdyn_arm64.dylib")
                res_mac = comp.compile_repositories(
                    [repo_dir],
                    dylib_path,
                    target_format="shared_lib",
                    entry_export="dyn_heap_kernel",
                    target_os="macos",
                    target_arch="arm64",
                    export_all=True,
                )
                self.assertTrue(res_mac["success"], res_mac)
                with open(dylib_path, "rb") as bf:
                    mac_audit = auditor.audit_binary(bf.read())
                self.assertTrue(mac_audit.is_valid, mac_audit)
                self.assertEqual(mac_audit.machine_arch, "ARM64")
                self.assertTrue(mac_audit.metrics.get("codesign_verified"))
                self.assertIn("/usr/lib/libSystem.B.dylib", mac_audit.metrics.get("dylib_dependencies", []))
                self.assertIn("malloc", mac_audit.metrics.get("dyld_bind_symbols", []))
                self.assertIn("free", mac_audit.metrics.get("dyld_bind_symbols", []))

                # 4. Execute natively on the current host via ctypes.CDLL
                sys_os = platform.system()
                sys_mach = platform.machine().lower()
                host_arch = "arm64" if ("arm" in sys_mach or "aarch64" in sys_mach) else "x86_64"
                if sys_os == "Windows":
                    host_bin = dll_path
                elif sys_os == "Darwin":
                    host_bin = os.path.join(td, "libhost.dylib")
                    res_h = comp.compile_repositories(
                        [repo_dir], host_bin, target_format="shared_lib", entry_export="dyn_heap_kernel", export_all=True
                    )
                    self.assertTrue(res_h["success"])
                else:
                    host_bin = os.path.join(td, f"libdyn_{host_arch}.so")

                lib = ctypes.CDLL(host_bin)
                try:
                    fn = lib.dyn_heap_kernel
                    fn.argtypes = [ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    # (12 * 10 + 7) + (12 + 3) = 127 + 15 = 142
                    self.assertEqual(fn(12), 142)
                    self.assertEqual(fn(0), 10)
                    self.assertEqual(fn(-4), -34)
                finally:
                    _unload_shared_lib(lib)
            finally:
                comp.close()

    def test_02_polyglot_arrays_structs_closures_and_imports(self):
        rust_src = """
use crate::geom::{scale_pt};
pub struct Point { pub x: i64, pub y: i64 }
pub fn rust_features(a: i64, b: i64) -> i64 {
    let mut p = Point { x: a, y: b };
    p.x = p.x + 10;
    let rep = [3; 4];
    let mul = |k: i64| k * 3;
    p.x + p.y + rep[2] + rep.len() + mul(4)
}
"""
        r_rs = lower_polyglot_source_to_ast(rust_src, "rust", strict=True)
        self.assertEqual(r_rs.imported_modules, ["crate::geom::scale_pt"])
        self.assertEqual([f.name for f in r_rs.functions], ["rust_features"])

        ts_src = """
import * as vec_math from "./vec_math";
export interface Pair { a: i64; b: i64; }
export function ts_features(v: number): number {
    const p: Pair = { a: v, b: 20 };
    const xs = [10, 20, 30];
    const bump = (z: number) => z + 7;
    return p.a + p.b + xs.length + bump(xs[1]);
}
"""
        r_ts = lower_polyglot_source_to_ast(ts_src, "typescript", strict=True)
        self.assertEqual(r_ts.imported_modules, ["./vec_math"])
        self.assertEqual([f.name for f in r_ts.functions], ["ts_features"])

        go_src = """
package main
import "math_lib"
type Box struct { w int64; h int64 }
func go_features(n int64) int64 {
    b := Box{w: n, h: 5}
    arr := []int64{3, 6, 9}
    dbl := func(k int64) int64 { return k * 2 }
    return b.w + b.h + arr[1] + dbl(n)
}
"""
        r_go = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        self.assertEqual(r_go.imported_modules, ["math_lib"])
        self.assertEqual([f.name for f in r_go.functions], ["go_features"])

        c_src = """
#include "geom.h"
struct Vec2 { int64_t x; int64_t y; };
int64_t c_features(int64_t n) {
    struct Vec2 v = { n, 4 };
    int64_t arr[3] = { 5, 10, 15 };
    return v.x + v.y + arr[1] + arr[2];
}
"""
        r_c = lower_polyglot_source_to_ast(c_src, "c", strict=True)
        self.assertEqual(r_c.imported_modules, ["geom.h"])
        self.assertEqual([f.name for f in r_c.functions], ["c_features"])

        # Compile each lowered single-repo kernel & verify host execution
        with tempfile.TemporaryDirectory() as td:
            comp = OmniRepoCompiler()
            try:
                ext = ".dll" if platform.system() == "Windows" else (".dylib" if platform.system() == "Darwin" else ".so")
                cases = [
                    ("rs_feat", "mod.rs", rust_src, "rust_features", (5, 7), 5 + 10 + 7 + 3 + 4 + 12),
                    ("ts_feat", "mod.ts", ts_src, "ts_features", (6,), 6 + 20 + 3 + 27),
                    ("go_feat", "mod.go", go_src, "go_features", (9,), 9 + 5 + 6 + 18),
                    ("c_feat", "mod.c", c_src, "c_features", (11,), 11 + 4 + 10 + 15),
                ]
                for idx, (rname, fname, code, sym, call_args, expected) in enumerate(cases):
                    rdir = os.path.join(td, rname)
                    os.makedirs(rdir, exist_ok=True)
                    with open(os.path.join(rdir, fname), "w", encoding="utf-8") as f:
                        f.write(code)
                    out_bin = os.path.join(td, f"{rname}_{idx}{ext}")
                    res = comp.compile_repositories(
                        [rdir], out_bin, target_format="shared_lib", entry_export=sym, export_all=True
                    )
                    self.assertTrue(res["success"], res)
                    lib = ctypes.CDLL(out_bin)
                    try:
                        fn = getattr(lib, sym)
                        fn.argtypes = [ctypes.c_int64] * len(call_args)
                        fn.restype = ctypes.c_int64
                        self.assertEqual(fn(*call_args), expected, f"Mismatch in {sym}")
                    finally:
                        _unload_shared_lib(lib)
            finally:
                comp.close()

    def test_03_multi_repo_4lang_oss_workload_e2e(self):
        c_src = """
#include "core_defs.h"
struct Vec2 { int64_t x; int64_t y; };
int64_t c_vec_kernel(int64_t n) {
    struct Vec2 v = { n, 4 };
    int64_t arr[3] = { 5, 10, 15 };
    return v.x + v.y + arr[1] + arr[2];
}
"""
        go_src = """
package mathcore
import "c_geom"
type Box struct { w int64; h int64 }
func go_box_kernel(n int64) int64 {
    b := Box{w: n, h: 5}
    arr := []int64{3, 6, 9}
    dbl := func(k int64) int64 { return k * 2 }
    return b.w + b.h + arr[1] + dbl(n) + c_geom.c_vec_kernel(2)
}
"""
        rs_src = """
use crate::go_core::go_box_kernel;
pub struct Point { pub x: i64, pub y: i64 }
pub fn rust_poly_kernel(a: i64, b: i64) -> i64 {
    let mut p = Point { x: a, y: b };
    p.x = p.x + 10;
    let mut arr = [1, 2, 3, 4];
    arr[2] = arr[2] + 5;
    let mul = |k: i64| k * 3;
    let ptr = malloc(32);
    if ptr == 0 {
        return -1;
    }
    store_i64(ptr, 0, p.x + p.y + arr[2] + arr.len() + mul(4));
    let heap_val = load_i64(ptr, 0);
    free(ptr);
    heap_val + go_core::go_box_kernel(a)
}
"""
        ts_src = """
import * as rs_mod from "./rs_mod";
export interface Pair { a: i64; b: i64; }
export function ts_real_oss_entry(v: number): number {
    const p: Pair = { a: v, b: 20 };
    const xs = [10, 20, 30];
    const bump = (z: number) => z + 7;
    return rs_mod.rust_poly_kernel(p.a, p.b) + xs.length + bump(xs[1]);
}
"""
        with tempfile.TemporaryDirectory() as td:
            for dname, fname, src in (
                ("c_repo", "vec.c", c_src),
                ("go_repo", "box.go", go_src),
                ("rs_repo", "poly.rs", rs_src),
                ("ts_repo", "entry.ts", ts_src),
            ):
                rdir = os.path.join(td, dname)
                os.makedirs(rdir, exist_ok=True)
                with open(os.path.join(rdir, fname), "w", encoding="utf-8") as f:
                    f.write(src)

            ext = ".dll" if platform.system() == "Windows" else (".dylib" if platform.system() == "Darwin" else ".so")
            out_bin = os.path.join(td, f"polyglot_oss{ext}")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    [os.path.join(td, d) for d in ("c_repo", "go_repo", "rs_repo", "ts_repo")],
                    out_bin,
                    target_format="shared_lib",
                    entry_export="ts_real_oss_entry",
                    export_all=True,
                )
                self.assertTrue(res["success"], res)
                audit = res["stages"]["formal_audit"]
                self.assertTrue(audit["is_valid"])
                # Verify transitive OS dynamic imports recorded structurally
                joined_imps = " ".join(audit["imported_symbols"])
                self.assertIn("malloc", joined_imps)
                self.assertIn("free", joined_imps)

                lib = ctypes.CDLL(out_bin)
                try:
                    fn = lib.ts_real_oss_entry
                    fn.argtypes = [ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    # c_vec_kernel(2) = 2 + 4 + 10 + 15 = 31
                    # go_box_kernel(v) = v + 5 + 6 + 2*v + 31 = 3*v + 42
                    # rust_poly_kernel(v, 20) = (v + 10 + 20 + 8 + 4 + 12) + (3*v + 42) = 4*v + 96
                    # ts_real_oss_entry(v) = 4*v + 96 + 3 + 27 = 4*v + 126
                    for v in (0, 6, -5, 19):
                        self.assertEqual(fn(v), 4 * v + 126)
                finally:
                    _unload_shared_lib(lib)
            finally:
                comp.close()


if __name__ == "__main__":
    unittest.main()
