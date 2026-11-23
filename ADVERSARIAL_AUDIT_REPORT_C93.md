# Adversarial Audit Report — Alpha-C93

## Edge Cases Prevented & Verified
1. **Linux UAPI `landlock_path_beneath_attr` Struct Packing**:
   - The Linux kernel `<linux/landlock.h>` header declares `struct landlock_path_beneath_attr` with `__attribute__((packed))` (12 bytes: `uint64 allowed_access` + `int32 parent_fd`). Setting `_pack_ = 1` in `ctypes.Structure` avoids `EINVAL` on syscall 445 (`landlock_add_rule`).
2. **Regular File vs Directory Landlock Access Masks**:
   - Passing directory-only `READ_DIR` (`0x08`) to `landlock_add_rule` on a regular file such as `/dev/null` or `/etc/ld.so.cache` triggers `EINVAL` in kernel Landlock. Masked non-directories (`not os.path.isdir(...)`) to file-scoped rights (`mask & 0x0007`) and explicitly permitted `/dev/null` with `0x0006` (`READ_FILE | WRITE_FILE`).
3. **Clean gRPC Server & ThreadPool Teardown**:
   - `REAPIGrpcServer.stop()` waits on `server.stop(0)` and calls `self._pool.shutdown(wait=True)` so Python `-W error::ResourceWarning` passes cleanly.
