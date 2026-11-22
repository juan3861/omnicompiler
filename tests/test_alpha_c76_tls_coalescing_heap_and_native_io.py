"""
Alpha-C76: Thread-Local Coalescing Heap Arenas & Native C-ABI File/TCP-HTTP I/O Tests.
"""

import ctypes
import http.server
import os
import tempfile
import threading
import unittest

from runtime.native_heap import (
    NATIVE_COLLECTION_SYMBOLS,
    _TLS_POOL,
    omni_alloc_tls,
    omni_free_tls,
    omni_heap_stats,
)
from runtime.native_io import (
    omni_file_close,
    omni_file_open,
    omni_file_read,
    omni_file_write,
    omni_tcp_http_request,
)


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OMNI_C76_OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class TestAlphaC76TlsCoalescingHeapAndNativeIo(unittest.TestCase):
    def test_01_thread_local_arenas_and_adjacent_block_coalescing(self):
        """
        Proves contention-free per-thread arenas + left/right adjacent block coalescing
        and exact address reuse across 8 concurrent worker threads.
        """
        _TLS_POOL.release_all()
        errors = []
        reused_matches = []
        lock = threading.Lock()

        def worker():
            try:
                p1 = omni_alloc_tls(64)
                p2 = omni_alloc_tls(64)
                p3 = omni_alloc_tls(64)
                self.assertEqual(p2 - p1, 64)
                self.assertEqual(p3 - p2, 64)

                # Free p1, then p3, then middle block p2 -> triggers both left and right coalescing
                self.assertEqual(omni_free_tls(p1), 1)
                self.assertEqual(omni_free_tls(p3), 1)
                self.assertEqual(omni_free_tls(p2), 1)

                # Re-allocate full 192 bytes -> must coalesce and reuse p1's exact address
                p_big = omni_alloc_tls(192)
                with lock:
                    reused_matches.append(p_big == p1)
                self.assertEqual(omni_free_tls(p_big), 1)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        try:
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10.0)
                self.assertFalse(t.is_alive())

            self.assertEqual(errors, [])
            self.assertEqual(len(reused_matches), 8)
            self.assertTrue(all(reused_matches))

            stats = omni_heap_stats()
            self.assertGreaterEqual(stats["thread_arenas"], 8)
            self.assertGreaterEqual(stats["coalesce_count"], 16)
            self.assertGreaterEqual(stats["reused_bytes"], 8 * 192)
            self.assertEqual(stats["active_allocations"], 0)
        finally:
            _TLS_POOL.release_all()

    def test_02_native_c_abi_file_io_and_tcp_http_loopback(self):
        """
        Proves C-ABI file descriptor I/O (`omni_file_open/write/read/close`) and
        native TCP/HTTP request (`omni_tcp_http_request`) via raw pointers.
        """
        for sym in (
            "omni_alloc_tls",
            "omni_free_tls",
            "omni_file_open",
            "omni_file_write",
            "omni_file_read",
            "omni_file_close",
            "omni_tcp_http_request",
        ):
            self.assertIn(sym, NATIVE_COLLECTION_SYMBOLS)

        with tempfile.TemporaryDirectory() as td:
            fpath = os.path.join(td, "c76_native_io.bin").encode("utf-8")
            path_buf = ctypes.create_string_buffer(fpath)
            payload = b"OMNI_NATIVE_FILE_C76_PAYLOAD"
            wbuf = ctypes.create_string_buffer(payload, len(payload))

            fd_w = omni_file_open(ctypes.addressof(path_buf), 1, 0o600)
            self.assertGreaterEqual(fd_w, 0)
            written = omni_file_write(fd_w, ctypes.addressof(wbuf), len(payload))
            self.assertEqual(written, len(payload))
            self.assertEqual(omni_file_close(fd_w), 0)

            rbuf = ctypes.create_string_buffer(64)
            fd_r = omni_file_open(ctypes.addressof(path_buf), 0, 0)
            self.assertGreaterEqual(fd_r, 0)
            nread = omni_file_read(fd_r, ctypes.addressof(rbuf), 64)
            self.assertEqual(nread, len(payload))
            self.assertEqual(omni_file_close(fd_r), 0)
            self.assertEqual(rbuf.raw[:nread], payload)

        srv = http.server.HTTPServer(("127.0.0.1", 0), _HealthHandler)
        port = srv.server_address[1]
        srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_thread.start()
        try:
            host_buf = ctypes.create_string_buffer(b"127.0.0.1")
            req_bytes = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            req_buf = ctypes.create_string_buffer(req_bytes, len(req_bytes))
            resp_buf = ctypes.create_string_buffer(4096)

            nrecv = omni_tcp_http_request(
                ctypes.addressof(host_buf),
                port,
                ctypes.addressof(req_buf),
                len(req_bytes),
                ctypes.addressof(resp_buf),
                4096,
            )
            self.assertGreater(nrecv, 0)
            resp_text = resp_buf.raw[:nrecv].decode("utf-8", errors="replace")
            self.assertIn("200 OK", resp_text)
            self.assertIn("OMNI_C76_OK", resp_text)
        finally:
            srv.shutdown()
            srv.server_close()
            srv_thread.join(timeout=5.0)
