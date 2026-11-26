"""Alpha-C112 verification: Rust Cargo.lock, vendor/offline Cargo DAG, build.rs & CycloneDX SBOM."""

import json
import os
import sys
import tempfile
import unittest

from frontends.toolchain_federation import FederatedBuildAdapter
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC112CargoLockDeps(unittest.TestCase):
    def test_01_cargo_lock_external_deps_vendor_build_rs_and_cyclonedx_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor_crate = os.path.join(tmp, "vendor", "tiny_hash")
            os.makedirs(os.path.join(vendor_crate, "src"), exist_ok=True)
            os.makedirs(os.path.join(tmp, ".cargo"), exist_ok=True)
            os.makedirs(os.path.join(tmp, "src"), exist_ok=True)

            with open(os.path.join(tmp, ".cargo", "config.toml"), "w", encoding="utf-8") as f:
                f.write('[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "vendor"\n')

            with open(os.path.join(vendor_crate, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "tiny_hash"\nversion = "0.4.2"\nedition = "2021"\n')
            with open(os.path.join(vendor_crate, "src", "lib.rs"), "w", encoding="utf-8") as f:
                f.write("pub fn mix32(x: u32) -> u32 { x.wrapping_mul(2654435761) ^ 0xA5A5 }\n")
            with open(os.path.join(vendor_crate, ".cargo-checksum.json"), "w", encoding="utf-8") as f:
                f.write('{"files":{}}')

            with open(os.path.join(tmp, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write(
                    '[package]\n'
                    'name = "c112_app"\n'
                    'version = "1.2.0"\n'
                    'edition = "2021"\n\n'
                    '[lib]\n'
                    'crate-type = ["staticlib"]\n\n'
                    '[dependencies]\n'
                    'tiny_hash = "0.4.2"\n'
                )
            with open(os.path.join(tmp, "Cargo.lock"), "w", encoding="utf-8") as f:
                f.write(
                    'version = 3\n\n'
                    '[[package]]\n'
                    'name = "c112_app"\n'
                    'version = "1.2.0"\n'
                    'dependencies = ["tiny_hash"]\n\n'
                    '[[package]]\n'
                    'name = "tiny_hash"\n'
                    'version = "0.4.2"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
                )
            with open(os.path.join(tmp, "build.rs"), "w", encoding="utf-8") as f:
                f.write(
                    'use std::{env, fs, path::Path};\n'
                    'fn main() {\n'
                    '    let out = env::var("OUT_DIR").unwrap();\n'
                    '    fs::write(Path::new(&out).join("c112_gen.rs"), "pub const BUILD_MAGIC: u32 = 112;").unwrap();\n'
                    '}\n'
                )
            with open(os.path.join(tmp, "src", "lib.rs"), "w", encoding="utf-8") as f:
                f.write(
                    'include!(concat!(env!("OUT_DIR"), "/c112_gen.rs"));\n'
                    '#[no_mangle]\n'
                    'pub extern "C" fn c112_rust_eval(v: u32) -> u32 { tiny_hash::mix32(v).wrapping_add(BUILD_MAGIC) }\n'
                )
            with open(os.path.join(tmp, "entry.py"), "w", encoding="utf-8") as f:
                f.write("def c112_stub(x: int) -> int:\n    return x + 1\n")

            adapter = FederatedBuildAdapter(target_os="linux" if sys.platform != "win32" else "windows")
            ws_info = adapter.inspect_cargo_workspace(tmp)
            self.assertTrue(ws_info["has_cargo_lock"])
            self.assertTrue(ws_info["has_vendor"])
            self.assertTrue(ws_info["has_build_rs"])
            self.assertIn("tiny_hash", ws_info["external_deps"])
            pkg_map = {p["name"]: p for p in ws_info["lock_packages"]}
            self.assertEqual(pkg_map["tiny_hash"]["version"], "0.4.2")
            self.assertEqual(pkg_map["tiny_hash"]["checksum"], "a" * 64)

            if adapter.native_tools.get("cargo") or (sys.platform == "win32" and adapter.wsl_tools.get("cargo")):
                arts = adapter._compile_cargo_workspace(tmp, "c112_rust_repo")
                self.assertGreater(len(arts), 0)
                self.assertIn("cargo", arts[0].toolchain_used)

            # Verify CycloneDX 1.5 SBOM captures locked Rust crates & checksums automatically
            out_base = os.path.join(tmp, "c112_out_bin")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[tmp],
                    output_path=out_base,
                    target_format="shared_lib",
                    entry_export="c112_stub",
                    toolchain_mode="aot_only",
                    emit_provenance=True,
                )
            finally:
                comp.close()
            sbom_path = res["sbom_path"]
            with open(sbom_path, "r", encoding="utf-8") as sf:
                sbom = json.load(sf)
            purls = {c.get("purl"): c for c in sbom.get("components", []) if c.get("purl")}
            self.assertIn("pkg:cargo/tiny_hash@0.4.2", purls)
            self.assertEqual(purls["pkg:cargo/tiny_hash@0.4.2"]["hashes"][0]["content"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
