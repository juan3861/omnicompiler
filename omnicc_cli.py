"""
Alpha-C100: Production `omnicc` Unified CLI Driver (`omnicc_cli.py`).

Subcommands:
  omnicc build       --repos ... --output ... [--backend ...] [--sanitize ...] [--repro-check]
  omnicc verify      --artifact <bin> [--provenance <intoto.jsonl>] [--sbom <cdx.json>]
  omnicc fuzz        --repo <dir> --fn <name> [--vectors 30]
  omnicc bench       [--out-json ...]
  omnicc lsp         (starts stdio JSON-RPC 2.0 Language Server)
  omnicc toolchains  (prints detected native + WSL2 toolchains & sandboxes)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from typing import Any, Dict, List, Optional


def _cmd_build(args: argparse.Namespace) -> int:
    from omni_repo_compiler import OmniRepoCompiler

    repo_list = [p.strip() for p in args.repos.split(",") if p.strip()]
    if not repo_list:
        raise ValueError("At least one repository path is required for --repos")

    compiler = OmniRepoCompiler()
    try:
        res = compiler.compile_repositories(
            repo_paths=repo_list,
            output_path=args.output,
            target_format=args.format,
            entry_export=args.entry,
            target_os=args.target_os,
            target_arch=args.arch,
            export_all=args.export_all,
            backend=args.backend,
            toolchain_mode=args.toolchain_mode,
            emit_provenance=(not args.no_provenance),
            verify_reproducibility=args.repro_check,
            sanitize=args.sanitize,
        )
    finally:
        compiler.close()

    if args.json:
        summary = {
            "success": bool(res.get("success")),
            "artifact_path": res["stages"]["emission"]["artifact_path"],
            "sbom_path": res.get("sbom_path"),
            "provenance_path": res.get("provenance_path"),
            "reproducibility": res["stages"].get("reproducibility"),
            "sanitizers": res["stages"].get("sanitizers"),
            "federation": res["stages"].get("federation"),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"[omnicc] Built: {res['stages']['emission']['artifact_path']}")
        if res.get("sbom_path"):
            print(f"[omnicc] SBOM:  {res['sbom_path']}")
        if res.get("provenance_path"):
            print(f"[omnicc] SLSA:  {res['provenance_path']}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from packaging.slsa_provenance import SLSAProvenanceGenerator

    art_path = os.path.abspath(args.artifact)
    prov_path = os.path.abspath(args.provenance or (art_path + ".intoto.jsonl"))
    sbom_path = os.path.abspath(args.sbom or (art_path + ".cdx.json"))

    if not os.path.exists(art_path):
        print(json.dumps({"valid": False, "reason": f"MISSING_ARTIFACT:{art_path}"}))
        return 2
    if not os.path.exists(prov_path):
        print(json.dumps({"valid": False, "reason": f"MISSING_PROVENANCE:{prov_path}"}))
        return 2

    with open(prov_path, "r", encoding="utf-8") as pf:
        envelope = json.loads(pf.read().strip())
    expected_sbom: Optional[Dict[str, Any]] = None
    if os.path.exists(sbom_path):
        with open(sbom_path, "r", encoding="utf-8") as sf:
            expected_sbom = json.load(sf)

    ver = SLSAProvenanceGenerator.verify_bundle(
        envelope,
        subjects_data={os.path.basename(art_path): art_path},
        expected_sbom=expected_sbom,
    )
    out_payload = {
        "valid": bool(ver.get("valid")),
        "reason": ver.get("reason"),
        "keyid": ver.get("keyid"),
        "artifact": art_path,
    }
    print(json.dumps(out_payload, sort_keys=True))
    return 0 if ver.get("valid") else 1


def _cmd_fuzz(args: argparse.Namespace) -> int:
    from compiler.ssa_ir import lower_ast_to_ssa
    from validation.differential_fuzzer import DifferentialFuzzer

    target_file = os.path.abspath(args.file)
    with open(target_file, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=target_file)
    fn_def = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == args.fn:
            fn_def = node
            break
    if fn_def is None:
        print(json.dumps({"passed": False, "error": f"Function '{args.fn}' not found in {target_file}"}))
        return 2

    ssa_fn = lower_ast_to_ssa(fn_def, optimize=True)
    backends = tuple(b.strip() for b in args.backends.split(",") if b.strip())
    fuzzer = DifferentialFuzzer(seed=args.seed, num_random_vectors=args.vectors)
    rep = fuzzer.fuzz_ssa_function(ssa_fn, backends=backends)
    print(json.dumps({
        "function": rep.function_name,
        "backends_compared": rep.backends_compared,
        "vectors_tested": rep.vectors_tested,
        "mismatches": rep.mismatches,
        "passed": rep.passed,
    }, sort_keys=True))
    return 0 if rep.passed else 1


def _cmd_bench(args: argparse.Namespace) -> int:
    from benchmarks.spec_class_suite import run_spec_class_suite

    res = run_spec_class_suite()
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, sort_keys=True)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0 if res.get("all_passed") else 1


def _cmd_toolchains(_args: argparse.Namespace) -> int:
    from frontends.toolchain_federation import ToolchainRegistry
    from orchestrator.rbe_cas import OSSandboxController

    info = {
        "native_tools": ToolchainRegistry.discover(),
        "wsl_tools": ToolchainRegistry.discover_wsl(),
        "sandbox": OSSandboxController.probe_capabilities(),
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def _cmd_lsp(_args: argparse.Namespace) -> int:
    from lsp.omnicc_lsp import run_stdio_server

    return run_stdio_server()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="omnicc", description="OmniCompiler Top-1 Industrial Polyglot Compiler Driver")
    sub = parser.add_subparsers(dest="command", required=True)

    p_b = sub.add_parser("build", help="Compile multi-repo polyglot sources into verified native binaries")
    p_b.add_argument("--repos", required=True, help="Comma-separated repository paths")
    p_b.add_argument("--output", required=True, help="Output binary base path")
    p_b.add_argument("--format", default="shared_lib", choices=["shared_lib", "executable"])
    p_b.add_argument("--target-os", choices=["windows", "linux", "macos"])
    p_b.add_argument("--arch", default="x86_64", choices=["x86_64", "arm64", "riscv64"])
    p_b.add_argument("--backend", default="native", choices=["native", "llvm", "gcc", "wasm", "homeostasis"])
    p_b.add_argument("--toolchain-mode", default="auto", choices=["auto", "aot_only", "federated_lto"])
    p_b.add_argument("--sanitize", default=None, help="Enable sanitizers e.g. 'asan,ubsan'")
    p_b.add_argument("--entry", default="omni_main")
    p_b.add_argument("--export-all", action="store_true")
    p_b.add_argument("--no-provenance", action="store_true")
    p_b.add_argument("--repro-check", action="store_true")
    p_b.add_argument("--json", action="store_true")
    p_b.set_defaults(func=_cmd_build)

    p_v = sub.add_parser("verify", help="Verify Ed25519 DSSE SLSA v1.0 provenance and CycloneDX SBOM")
    p_v.add_argument("--artifact", required=True)
    p_v.add_argument("--provenance", default=None)
    p_v.add_argument("--sbom", default=None)
    p_v.set_defaults(func=_cmd_verify)

    p_f = sub.add_parser("fuzz", help="Differential fuzz a Python function across native, LLVM, and WASM backends")
    p_f.add_argument("--file", required=True)
    p_f.add_argument("--fn", required=True)
    p_f.add_argument("--backends", default="native,llvm,wasm")
    p_f.add_argument("--vectors", type=int, default=20)
    p_f.add_argument("--seed", type=int, default=20261124)
    p_f.set_defaults(func=_cmd_fuzz)

    p_bench = sub.add_parser("bench", help="Run the 7 SPEC-class bit-exact native benchmark suite")
    p_bench.add_argument("--out-json", default=None)
    p_bench.set_defaults(func=_cmd_bench)

    p_tc = sub.add_parser("toolchains", help="Inspect host native & WSL2 federated toolchains")
    p_tc.set_defaults(func=_cmd_toolchains)

    p_lsp = sub.add_parser("lsp", help="Launch JSON-RPC 2.0 Language Server over stdio")
    p_lsp.set_defaults(func=_cmd_lsp)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
