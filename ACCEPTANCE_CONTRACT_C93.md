# Acceptance Contract — Alpha-C93 (Real gRPC HTTP/2 REAPI v2, Merkle Tree & Landlock LSM)

## Scope
1. **`orchestrator/rbe_cas.py` (`ContentAddressableStore`)**: Added `put_merkle_tree` and `materialize_merkle_tree` creating sorted deterministic Bazel `Directory`/`Tree` digests in CAS with path-traversal protection.
2. **`orchestrator/rbe_cas.py` (`REAPIGrpcServer` / `REAPIGrpcClient`)**: Real HTTP/2 gRPC transport using `grpcio` and `google.protobuf.struct_pb2.Struct` serving Bazel REAPI v2 RPCs (`GetCapabilities`, `FindMissingBlobs`, `BatchUpdateBlobs`, `BatchReadBlobs`, `GetActionResult`, `Execute`, `ExecuteRaw`) and integrated directly with `RBECoordinator.execute_dag_bwob`.
3. **`orchestrator/rbe_cas.py` (`OSSandboxController`)**: Real Linux Kernel Landlock LSM (`landlock_create_ruleset`, `landlock_add_rule` with 12-byte packed `landlock_path_beneath_attr`, `landlock_restrict_self`) restricting child processes strictly to `sandbox_dir` (r/w) and system runtime libs (r/o) alongside `prctl(PR_SET_NO_NEW_PRIVS)` and `resource.setrlimit`.

## Verification Criteria
- `test_01_bazel_merkle_tree_cas_roundtrip` proves deterministic Tree/Directory CAS ingestion & restoration.
- `test_02_real_grpc_http2_reapi_v2_and_bwob_dag` runs two HTTP/2 gRPC servers + BwoB DAG cleanly with zero `ResourceWarning`.
- `test_03_os_sandbox_and_linux_landlock_escape_enforcement` runs cleanly locally and proves `PermissionError` (`EACCES`) against filesystem escape on Linux CI.
