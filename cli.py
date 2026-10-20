"""
Repository Compiler CLI: Operator interface supporting submit, run, status, explain, and export.
"""

import argparse
import sys
import os
import json

# Ensure repository-compiler root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contracts.models import IntegrationSpec
from controller.orchestrator import RunController


def main():
    parser = argparse.ArgumentParser(description="Repository Compiler CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Submit & Run
    run_parser = subparsers.add_parser("run", help="Submit and execute an integration spec")
    run_parser.add_argument("--spec", required=True, help="Path to IntegrationSpec JSON")
    run_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Submit only
    sub_parser = subparsers.add_parser("submit", help="Submit an integration spec and return run_id")
    sub_parser.add_argument("--spec", required=True, help="Path to IntegrationSpec JSON")
    sub_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Status
    status_parser = subparsers.add_parser("status", help="Query run status")
    status_parser.add_argument("--run-id", required=True, help="Run ID")
    status_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Explain
    explain_parser = subparsers.add_parser("explain", help="Explain requirement resolution and verification")
    explain_parser.add_argument("--run-id", required=True, help="Run ID")
    explain_parser.add_argument("--requirement-id", default=None, help="Optional requirement ID filter")
    explain_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Cancel
    cancel_parser = subparsers.add_parser("cancel", help="Cancel a run")
    cancel_parser.add_argument("--run-id", required=True, help="Run ID")
    cancel_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Resume
    resume_parser = subparsers.add_parser("resume", help="Validate checkpoint digests and resume a run")
    resume_parser.add_argument("--run-id", required=True, help="Run ID")
    resume_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    # Export
    export_parser = subparsers.add_parser("export", help="Export accepted package, manifest, and evidence")
    export_parser.add_argument("--run-id", required=True, help="Run ID")
    export_parser.add_argument("--dest", required=True, help="Destination directory for export")
    export_parser.add_argument("--workdir", default="./.rc_workspace", help="Working directory for runs")

    args = parser.parse_args()
    controller = RunController(workdir=args.workdir)

    if args.command == "run":
        with open(args.spec, "r", encoding="utf-8") as f:
            spec_data = json.load(f)
        spec = IntegrationSpec(**spec_data)
        run_id = controller.submit(spec)
        print(f"[*] Submitted run: {run_id}")
        print(f"[*] Executing pipeline...")
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

