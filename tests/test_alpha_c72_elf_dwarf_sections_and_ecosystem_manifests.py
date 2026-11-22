"""
Alpha-C72 Validation Suite:
1. Materialization of DWARF v5 `.debug_info`, `.debug_abbrev`, and `.debug_line` as real ELF64
   sections inside emitted `.so` shared libraries (verified via `pyelftools` & `BinaryStructureAuditor`
   and `DwarfV5Emitter.decode_debug_line`).
2. Ecosystem Manifest Auto-Discovery (`Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`)
   and cross-repo polyglot compilation without manual `omni.toml`.
"""

import io
import os
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

from compiler.debug_info_emitter import DwarfV5Emitter
from omni_repo_compiler import OmniRepoCompiler
from orchestrator.repo_manifest_ingestor import RepoManifestIngestor
from validation.binary_structure_auditor import BinaryStructureAuditor
from validation.validator import IndependentValidator


class TestAlphaC72ElfDwarfSectionsAndEcosystemManifests(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_elf64_so_embeds_real_dwarf_v5_sections_via_pyelftools(self):
        """
        Proves `OmniRepoCompiler` materializes `.debug_info`, `.debug_abbrev`, and `.debug_line`
        inside emitted Linux ELF64 `.so` binaries, readable by `pyelftools` and `DwarfV5Emitter.decode_debug_line`.
        """
        src = """
def helper_sq(n: int) -> int:
    return n * n + 1

def omni_main(x: int) -> int:
    return helper_sq(x) + 4
"""
        with tempfile.TemporaryDirectory() as td:
            rdir = os.path.join(td, "repo_dwarf_elf")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, "calc.py"), "w", encoding="utf-8") as f:
                f.write(src)
            with open(os.path.join(rdir, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_dwarf_elf"\n'
                    'version = "1.0.0"\n'
                    'exports = [\n'
                    '  { name = "helper_sq", file = "calc.py", args = ["n"], return_type = "int" },\n'
                    '  { name = "omni_main", file = "calc.py", args = ["x"], return_type = "int" }\n'
                    ']\n'
                    'imports = []\n'
                )

            out_so = os.path.join(td, "libdwarf_c72.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[rdir],
                    output_path=out_so,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    target_os="linux",
                    target_arch="x86_64",
                    backend="native",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            so_path = res["stages"]["emission"]["artifact_path"]
            with open(so_path, "rb") as f:
                elf_bytes = f.read()

            rep = BinaryStructureAuditor().audit_binary(elf_bytes)
            self.assertTrue(rep.is_valid, f"ELF audit errors: {rep.errors}")
            self.assertIn(".debug_info", rep.sections)
            self.assertIn(".debug_abbrev", rep.sections)
            self.assertIn(".debug_line", rep.sections)
            self.assertIn("omni_main", rep.exported_symbols)

            elf = ELFFile(io.BytesIO(elf_bytes))
            dbg_line_sec = elf.get_section_by_name(".debug_line")
            dbg_info_sec = elf.get_section_by_name(".debug_info")
            self.assertIsNotNone(dbg_line_sec)
            self.assertIsNotNone(dbg_info_sec)
            decoded = DwarfV5Emitter().decode_debug_line(dbg_line_sec.data())
            self.assertEqual(decoded["version"], 5)
            self.assertGreaterEqual(len(decoded["rows"]), 2)
            self.assertIn(b"omni_main\x00", dbg_info_sec.data())

    def test_02_ecosystem_manifest_auto_discovery_without_omni_toml(self):
        """
        Proves `RepoManifestIngestor` auto-discovers `Cargo.toml`, `package.json`, `go.mod`,
        and `pyproject.toml` dependencies and compiles polyglot repositories without manual `omni.toml`.
        """
        with tempfile.TemporaryDirectory() as td:
            r_rs = os.path.join(td, "crate_math")
            r_ts = os.path.join(td, "ts_svc")
            r_go = os.path.join(td, "go_app")
            r_py = os.path.join(td, "py_cfg")
            for d in (r_rs, r_ts, r_go, r_py):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(r_rs, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "crate_math"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0"\n')
            with open(os.path.join(r_rs, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("pub fn rs_mul(x: i64) -> i64 { return x * 4; }\n")

            with open(os.path.join(r_ts, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name": "ts_svc", "dependencies": {"zod": "^3.0.0"}}')
            with open(os.path.join(r_ts, "svc.ts"), "w", encoding="utf-8") as f:
                f.write("export function ts_add(x: number): number { return rs_mul(x) + 9; }\n")

            with open(os.path.join(r_go, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module example.com/go_app\n\ngo 1.22\n\nrequire golang.org/x/sys v0.18.0\n")
            with open(os.path.join(r_go, "main.go"), "w", encoding="utf-8") as f:
                f.write("package main\nfunc omni_main(x int64) int64 { return ts_add(x) + 1 }\n")

            with open(os.path.join(r_py, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write('[project]\nname = "py_cfg"\ndependencies = ["z3-solver>=4.12"]\n')
            with open(os.path.join(r_py, "cfg.py"), "w", encoding="utf-8") as f:
                f.write("def py_bias(x: int) -> int:\n    return x + 2\n")

            ingestor = RepoManifestIngestor()
            m_rs = ingestor.ingest_repository(r_rs)
            m_ts = ingestor.ingest_repository(r_ts)
            m_go = ingestor.ingest_repository(r_go)
            m_py = ingestor.ingest_repository(r_py)

            self.assertEqual(m_rs.repo_type, "rust")
            self.assertIn("cargo:serde", m_rs.package_dependencies)
            self.assertEqual(m_ts.repo_type, "typescript")
            self.assertIn("npm:zod", m_ts.package_dependencies)
            self.assertEqual(m_go.repo_type, "go")
            self.assertIn("go:golang.org/x/sys", m_go.package_dependencies)
            self.assertEqual(m_py.repo_type, "python")
            self.assertIn("pypi:z3-solver", m_py.package_dependencies)

            # End-to-end compile without any omni.toml:
            # omni_main(10) = (10 * 4 + 9) + 1 = 50
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[r_rs, r_ts, r_go],
                    output_path=os.path.join(td, "auto_poly.so"),
                    target_format="shared_lib",
                    entry_export="omni_main",
                    target_os="linux",
                    target_arch="x86_64",
                    backend="homeostasis",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 50)


if __name__ == "__main__":
    unittest.main()
