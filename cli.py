"""
Repository Compiler & OmniCompiler Unified CLI:
Supports both IntegrationSpec RunController workflows (submit, run, status, explain, cancel, resume, export)
and Native Multi-Repository Compilation & Verification subcommands (compile, audit-attest, egraph, cpg, alive, cegis, mcts, unified).
"""

import argparse
import sys
import os
import json

# Ensure repository-compiler root is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from contracts.models import IntegrationSpec
from controller.orchestrator import RunController


NATIVE_SUBCOMMANDS = {
    "compile",
    "audit-attest",
    "egraph",
    "cpg",
    "alive",
    "cegis",
    "mcts",
    "unified",
}


def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    # Delegate native OmniCompiler commands directly to omnicompiler_cli for 100% flag parity
    if raw_argv and raw_argv[0] in NATIVE_SUBCOMMANDS:
        import omnicompiler_cli
        old_argv = sys.argv
        try:
            sys.argv = [old_argv[0]] + raw_argv
            rc = omnicompiler_cli.main()
        finally:
            sys.argv = old_argv
        if rc:
            sys.exit(rc)
        return

    parser = argparse.ArgumentParser(
        description="OmniCompiler Unified CLI (Integration Orchestrator + Native Multi-Repo Compiler)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- IntegrationSpec RunController Commands ---
    run_parser = subparsers.add_parser("run", help="Submit and execute an integration spec")
    run_parser.add_argument("--spec", required=True, help="Path to IntegrationSpec JSON")
    run_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    sub_parser = subparsers.add_parser("submit", help="Submit an integration spec and return run_id")
    sub_parser.add_argument("--spec", required=True, help="Path to IntegrationSpec JSON")
    sub_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    status_parser = subparsers.add_parser("status", help="Query run status")
    status_parser.add_argument("--run-id", required=True, help="Run ID")
    status_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    explain_parser = subparsers.add_parser("explain", help="Explain requirement resolution and verification")
    explain_parser.add_argument("--run-id", required=True, help="Run ID")
    explain_parser.add_argument("--requirement-id", default=None, help="Optional requirement ID filter")
    explain_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    cancel_parser = subparsers.add_parser("cancel", help="Cancel a run")
    cancel_parser.add_argument("--run-id", required=True, help="Run ID")
    cancel_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    resume_parser = subparsers.add_parser("resume", help="Validate checkpoint digests and resume a run")
    resume_parser.add_argument("--run-id", required=True, help="Run ID")
    resume_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    export_parser = subparsers.add_parser("export", help="Export accepted package, manifest, and evidence")
    export_parser.add_argument("--run-id", required=True, help="Run ID")
    export_parser.add_argument("--dest", required=True, help="Destination directory for export")
    export_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # --- Native Compiler Subcommands (documented in --help, dispatched above) ---
    subparsers.add_parser("compile", help="Compile repositories into native PE/ELF/Mach-O shared lib or executable")
    subparsers.add_parser("audit-attest", help="Verify cryptographic provenance ledger of compiled binary")
    subparsers.add_parser("egraph", help="Run E-Graph equality saturation")
    subparsers.add_parser("cpg", help="Run CPG interprocedural taint reachability audit")
    subparsers.add_parser("alive", help="Run Alive2-style Z3 SMT refinement verification")
    subparsers.add_parser("cegis", help="Run CEGIS inductive synthesis")
    subparsers.add_parser("mcts", help="Run MCTS assembly instruction superoptimizer")
    subparsers.add_parser("unified", help="Run end-to-end multi-subsystem pipeline")

    args = parser.parse_args(raw_argv)
    controller = RunController(workdir=args.workdir)

    if args.command == "run":
        with open(args.spec, "r", encoding="utf-8") as f:
            spec_data = json.load(f)
        spec = IntegrationSpec(**spec_data)
        run_id = controller.submit(spec)
        print(f"[*] Submitted run: {run_id}")
        print("[*] Executing pipeline...")
        result = controller.execute_run(run_id)
        print(json.dumps(result, indent=2))
        if not result.get("ok"):
            sys.exit(1)

    elif args.command == "submit":
        with open(args.spec, "r", encoding="utf-8") as f:
            spec_data = json.load(f)
        spec = IntegrationSpec(**spec_data)
        run_id = controller.submit(spec)
        print(json.dumps({"run_id": run_id}))

    elif args.command == "status":
        info = controller.status(args.run_id)
        print(json.dumps(info, indent=2))

    elif args.command == "explain":
        info = controller.explain(args.run_id, args.requirement_id)
        print(json.dumps(info, indent=2))

    elif args.command == "cancel":
        info = controller.cancel(args.run_id)
        print(json.dumps(info, indent=2))

    elif args.command == "resume":
        info = controller.resume(args.run_id)
        print(json.dumps(info, indent=2))
        if not info.get("ok"):
            sys.exit(1)

    elif args.command == "export":
        info = controller.export(args.run_id, args.dest)
        print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
