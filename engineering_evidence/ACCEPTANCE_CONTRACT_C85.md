# Acceptance Contract - Alpha-C85: Bazel REAPI v2, BwoB & OS Kernel Sandbox

## Scope
Upgrade `orchestrator/rbe_cas.py` with:
1. Bazel Remote Execution API v2 HTTP/JSON endpoints and client (`REAPIClient`, `REAPIServerCapabilities`, `FindMissingBlobs`, `BatchUpdateBlobs`, `BatchReadBlobs`, `GetActionResult`, `UpdateActionResult`, `Execute`).
2. Build-without-the-Bytes (`RBECoordinator.execute_dag_bwob`) flowing CAS `Digest` references between remote workers with zero intermediate local disk materialization.
3. OS kernel worker sandbox (`OSSandboxController`) using Win32 Job Objects (`KILL_ON_JOB_CLOSE | PROCESS_MEMORY | ACTIVE_PROCESS`) on Windows and `resource.setrlimit` (+ Landlock capability probe) on POSIX.

## Empirical Gates
- `python -W error::ResourceWarning run_c85_tests.py` passes 100%.
- `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c85_tests.py` returns `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` passes `14/14`.
- Full `unittest discover` passes 100%.
