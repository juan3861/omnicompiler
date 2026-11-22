# Adversarial Audit Report — Alpha-C76

- **Contention & Coalescing Audit:** 8 concurrent threads allocated 3 adjacent blocks each (`p1`, `p2`, `p3`), freed outer blocks then middle block (`p1`, `p3`, `p2`), triggering bidirectional coalescing (`coalesce_count >= 16`), and reallocated 192 bytes reusing `p1`'s exact address in 8/8 threads with 0 leaks (`active_allocations == 0`).
- **C-ABI File & Network I/O Audit:** `omni_file_open/write/read/close` verified roundtrip raw pointer payload on disk; `omni_tcp_http_request` verified real HTTP/1.1 loopback roundtrip (`200 OK`, `OMNI_C76_OK`) with clean socket/server shutdown (`-W error::ResourceWarning`).
