# Acceptance Contract — Alpha-C76 (Thread-Local Coalescing Arenas, Native C-ABI I/O & Linux AArch64 CI)

## Scope
1. `runtime/native_heap.py`: `CoalescingHeapArena` (address-ordered free-list with left/right block coalescing), `ThreadLocalArenaPool` (zero-contention per-thread arenas), `omni_alloc_tls`, `omni_free_tls`, `omni_heap_stats`.
2. `runtime/native_io.py`: Freestanding C-ABI file descriptor I/O (`omni_file_open`, `omni_file_write`, `omni_file_read`, `omni_file_close`) and TCP/HTTP request primitive (`omni_tcp_http_request`) merged into `NATIVE_COLLECTION_SYMBOLS`.
3. `.github/workflows/ci.yml`: `verify-linux-arm64` job (`ubuntu-24.04-arm`) executing `run_c76_tests.py` + native `arm64_elf` execution (`exit_code == 42`).

## Verification Gates
- `run_c76_tests.py -W error::ResourceWarning`: `2/2 OK`.
- `AetherMind_Strict_Auditor.py run_c76_tests.py`: `APROVADO`.
- GitHub Actions 4-runner matrix (`ubuntu-latest`, `windows-latest`, `macos-latest`, `ubuntu-24.04-arm`): `success`.
